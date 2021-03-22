import gc
import hashlib
import json
import os
import re
from base64 import b64decode

from assemblyline.common.hexdump import hexdump
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT
from peepdf.ext.peepdf.JSAnalysis import analyseJS, unescape
from peepdf.ext.peepdf.PDFCore import PDFParser, vulnsDict

BANNED_TYPES = ["xref", "objstm", "xobject", "metadata", "3d", "pattern", None]


def validate_non_humanreadable_buff(data, buff_min_size=256, whitespace_ratio=0.10):
    ws_count = data.count(" ")
    ws_count += data.count("%20") * 3
    if len(data) >= buff_min_size:
        if ws_count * 1.0 / len(data) < whitespace_ratio:
            return True

    return False


# noinspection PyGlobalUndefined
class PeePDF(ServiceBase):

    CVE_FALSE_POSITIVES = ["CVE-2009-0658", "CVE-2010-0188"]

    def __init__(self, config=None):
        super().__init__(config)
        self.max_pdf_size = self.config.get('max_pdf_size', 3000000)

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def _report_embedded_xdp(self, file_res, chunk_number, binary, leftover):
        res_section = ResultSection([f"Found {chunk_number}", "Embedded PDF (in XDP)"])
        res_section.set_heuristic(1)
        res_section.add_tag('file.behavior', "Embedded PDF (in XDP)")
        file_res.add_section(res_section)

    def find_xdp_embedded(self, filename, cbin, request):
        file_res = request.result
        if "<pdf" in cbin and "<document>" in cbin and "<chunk>" in cbin:
            chunks = cbin.split("<chunk>")

            chunk_number = 0
            leftover = ""
            for chunk in chunks:
                if "</chunk>" not in chunk:
                    leftover += chunk.replace("<document>", "").replace('<pdf xmlns="http://ns.adobe.com/xdp/pdf/">',
                                                                        "")
                    continue

                chunk_number += 1

                un_b64 = None
                # noinspection PyBroadException
                try:
                    un_b64 = b64decode(chunk.split("</chunk>")[0])
                except Exception:
                    self.log.error("Found <pdf>, <document> and <chunk> tags inside an xdp file but could not "
                                   "un-base64 the content.")

                if un_b64:
                    new_filename = f"xdp_{chunk_number}.pdf"
                    file_path = os.path.join(self.working_directory, new_filename)
                    with open(file_path, "wb") as f:
                        f.write(un_b64)
                    request.add_extracted(file_path, os.path.basename(file_path), f"UnXDP from {filename}")

            if chunk_number > 0:
                self._report_embedded_xdp(file_res, chunk_number, cbin, leftover)

        return file_res

    def execute(self, request):
        request.result = Result()

        # Filter out large documents
        if os.path.getsize(request.file_path) > self.max_pdf_size:
            res = (ResultSection(f"PDF Analysis of the file was skipped because the "
                                 f"file is too big (limit is {(self.max_pdf_size / 1000 / 1000)} MB)."))

            request.result.add_section(res)
            return


        with open(request.file_path, 'rb') as f:
            file_contents = f.read()

        if '<xdp:xdp'.encode(encoding='UTF-8') in file_contents:
            filename = os.path.basename(request.file_path)
            self.find_xdp_embedded(filename, file_contents, request)

        # noinspection PyBroadException
        try:
            pdf_parser = PDFParser()
            ret, pdf_file = pdf_parser.parse(request.file_path, True, False, file_contents)
            if ret == 0:
                self.peepdf_analysis(pdf_file, file_contents, request)
            else:
                res = ResultSection("ERROR: Could not parse file with PeePDF.")
                request.result.add_section(res)
        finally:
            try:
                del pdf_file
            except Exception:
                pass

            try:
                del pdf_parser
            except Exception:
                pass

            gc.collect()

    # noinspection PyBroadException
    @staticmethod
    def get_big_buffs(data, buff_min_size=256):
        # Hunt for big variables
        var_re = r'[^\\]?"(.*?[^\\])"'
        last_m = None
        out = []

        for m in re.finditer(var_re, data):
            # noinspection PyUnresolvedReferences
            pos = m.regs[0]
            match = m.group(1)
            if last_m:
                last_pos, last_match = last_m
                between = data[last_pos[1]:pos[0] + 1]
                try:
                    between, rest = between.split("//", 1)
                    try:
                        between = between.strip() + rest.split("\n", 1)[1].strip()
                    except Exception:
                        pass
                except Exception:
                    pass
                finally:
                    between = between.strip()

                if between == "+":
                    match = last_match + match
                    pos = (last_pos[0], pos[1])
                else:
                    if validate_non_humanreadable_buff(last_match, buff_min_size=buff_min_size):
                        out.append(last_match)

            last_m = (pos, match)

        if last_m:
            if validate_non_humanreadable_buff(last_m[1]):
                out.append(last_m[1])

        # Hunt for big comments
        var_comm_re = r"<!--(.*?)--\s?>"

        for m in re.finditer(var_comm_re, data, flags=re.DOTALL):
            match = m.group(1)
            if validate_non_humanreadable_buff(match):
                out.append(match)

        return out

    @staticmethod
    def check_dangerous_func(data):
        has_eval = False
        has_unescape = False
        # eval
        temp_eval = data.split("eval")
        if len(temp_eval) > 1:
            for idx, i in enumerate(temp_eval[:-1]):
                if (97 <= ord(i[-1]) <= 122) or (65 <= ord(i[-1]) <= 90):
                    continue
                if (97 <= ord(temp_eval[idx][0]) <= 122) or \
                        (65 <= ord(temp_eval[idx][0]) <= 90):
                    continue

                has_eval = True
                break

        # unescape
        temp_unesc = data.split("unescape")
        if len(temp_unesc) > 1:
            for idx, i in enumerate(temp_unesc[:-1]):
                if (97 <= ord(i[-1]) <= 122) or (65 <= ord(i[-1]) <= 90):
                    continue
                if (97 <= ord(temp_unesc[idx][0]) <= 122) or \
                        (65 <= ord(temp_unesc[idx][0]) <= 90):
                    continue

                has_unescape = True
                break

        return has_eval, has_unescape

    @staticmethod
    def list_first_x(mylist, size=20):
        add_reminder = len(mylist) > size

        mylist = mylist[:size]
        if add_reminder:
            mylist.append("...")

        return mylist

    def analyze_javascript(self, js_code, unescaped_bytes, js_res, obj, request):
        """ Create section for javascript code blocks """
        buffers = False

        # Check for Eval and Unescape
        has_eval, has_unescape = self.check_dangerous_func(js_code)
        if has_eval:
            eval_res = ResultSection("[Suspicious Function] eval()", parent=js_res)

            eval_res.add_line("This JavaScript block uses eval() function "
                                      "which is often used to launch deobfuscated "
                                      "JavaScript code.")
            eval_res.set_heuristic(3)
        if has_unescape:
            unescape_res = ResultSection("[Suspicious Function] unescape()", parent=js_res)
            unescape.add_line("This JavaScript block uses unescape() "
                                      "function. It may be legitimate but it is definitely "
                                      "suspicious since malware often use this to "
                                      "deobfuscate code blocks.")
            unescape.set_heuristic(4)

        # Large Buffers
        big_buffs = self.get_big_buffs(js_code)
        for buff_idx, buff in enumerate(big_buffs):
            error, new_buff = unescape(buff)
            if error == 0:
                buff = new_buff

            if buff not in unescaped_bytes:
                temp_path_name = None
                if ";base64," in buff[:100] and "data:" in buff[:100]:
                    temp_path_name = f"obj{obj}_unb64_{buff_idx}.buff"
                    try:
                        buff = b64decode(buff.split(";base64,")[1].strip())
                        temp_path = os.path.join(self.working_directory, temp_path_name)
                        with open(temp_path, "wb") as f:
                            f.write(buff)
                        request.add_extracted(temp_path, os.path.basename(temp_path),
                                          f"Dumped from {os.path.basename(request.file_path)}")
                    except Exception:
                        self.log.error("Found 'data:;base64, ' buffer "
                                       "but failed to base64 decode.")
                        temp_path_name = None

                if temp_path_name is not None:
                    buff_cond = f" and was resubmitted as {temp_path_name}"
                else:
                    buff_cond = ""
                buff_res = ResultSection(
                    f"A {len(buff)} bytes buffer was found in the JavaScript "
                    f"block{buff_cond}. Here are the first 256 bytes.",
                    parent=js_res, body=hexdump(bytes(buff[:256], "utf-8")),
                    body_format=BODY_FORMAT.MEMORY_DUMP)
                buffers = True

        # Extract javascript block
        if has_eval or has_unescape or len(big_buffs > 0):
            js_res.add_tag('file.behaviour', "Suspicious Javascript in PDF")
            temp_js_outname = f"object{obj}-{version}_{js_idx}.js"
            temp_js_path = os.path.join(self.working_directory, temp_js_outname)
            temp_js_bin = js_code.encode("utf-8")
            with open(temp_js_path, "wb") as f:
                f.write(temp_js_bin)
            f_list.append(temp_js_path)
            js_res.add_line(f"The JavaScript block was saved as {temp_js_outname}")

        # Handle unescaped buffers
        for sc_idx, sc in enumerate(set(unescaped_bytes)):
            try:
                sc = sc.decode("hex")
            except Exception:
                pass

            temp_path_name = f"obj{obj}_unescaped_{sc_idx}.buff"

            shell_res = ResultSection(f"Unknown unescaped {len(sc)} bytes JavaScript "
                                      f"buffer (id: {sc_idx}) was resubmitted as "
                                      f"{temp_path_name}. Here are the first 256 bytes.",
                                      parent=js_res)
            shell_res.set_body(hexdump(sc[:256]), body_format=BODY_FORMAT.MEMORY_DUMP)

            temp_path = os.path.join(self.working_directory, temp_path_name)
            with open(temp_path, "wb") as f:
                f.write(sc)
            f_list.append(temp_path)

            js_res.add_tag('file.behavior', "Unescaped JavaScript Buffer")
            shell_res.set_heuristic(6)

        return buffers

    # noinspection PyBroadException,PyUnboundLocalVariable
    def peepdf_analysis(self, pdf_file, file_content, request):
        temp_filename = request.file_path
        res_list = []
        # js_stream = []
        f_list = []
        js_dump = []

        stats_dict = pdf_file.getStats()

        if ", ".join(stats_dict['Errors']) == "Bad PDF header, %%EOF not found, PDF sections not found, No " \
                                              "indirect objects found in the body":
            # Not a PDF
            return

        json_body = dict(
            version=stats_dict['Version'],
            binary=stats_dict['Binary'],
            linearized=stats_dict['Linearized'],
            encrypted=stats_dict['Encrypted'],
        )

        if stats_dict['Encryption Algorithms']:
            temp = []
            for algorithm_info in stats_dict['Encryption Algorithms']:
                temp.append(f"{algorithm_info[0]} {str(algorithm_info[1])} bits")
            json_body["encryption_algorithms"] = temp

        json_body.update(dict(
            updates=stats_dict['Updates'],
            objects=stats_dict['Objects'],
            streams=stats_dict['Streams'],
            comments=stats_dict['Comments'],
            errors={True: ", ".join(stats_dict['Errors']),
                    False: "None"}[len(stats_dict['Errors']) != 0]
        ))
        res = ResultSection("PDF File Information", body_format=BODY_FORMAT.KEY_VALUE,
                            body=json.dumps(json_body))

        for version in range(len(stats_dict['Versions'])):
            stats_version = stats_dict['Versions'][version]
            v_json_body = dict(
                catalog=stats_version['Catalog'] or "no",
                info=stats_version['Info'] or "no",
                objects=self.list_first_x(stats_version['Objects'][1]),
            )

            if stats_version['Compressed Objects'] is not None:
                v_json_body['compressed_objects'] = self.list_first_x(stats_version['Compressed Objects'][1])

            if stats_version['Errors'] is not None:
                v_json_body['errors'] = self.list_first_x(stats_version['Errors'][1])

            v_json_body['streams'] = self.list_first_x(stats_version['Streams'][1])

            if stats_version['Xref Streams'] is not None:
                v_json_body['xref_streams'] = self.list_first_x(stats_version['Xref Streams'][1])

            if stats_version['Object Streams'] is not None:
                v_json_body['object_streams'] = self.list_first_x(stats_version['Object Streams'][1])

            if int(stats_version['Streams'][0]) > 0:
                v_json_body['encoded'] = self.list_first_x(stats_version['Encoded'][1])
                if stats_version['Decoding Errors'] is not None:
                    v_json_body['decoding_errors'] = self.list_first_x(stats_version['Decoding Errors'][1])

            if stats_version['Objects with JS code'] is not None:
                v_json_body['objects_with_js_code'] = \
                    self.list_first_x(stats_version['Objects with JS code'][1])
                # js_stream.extend(stats_version['Objects with JS code'][1])

            res_version = ResultSection(f"Version {str(version)}", parent=res,
                                        body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(v_json_body))

            actions = stats_version['Actions']
            events = stats_version['Events']
            vulns = stats_version['Vulns']
            elements = stats_version['Elements']
            if events is not None or actions is not None or vulns is not None or elements is not None:
                res_suspicious = ResultSection('Suspicious elements', parent=res_version)
                res_suspicious.set_heuristic(8)
                if events is not None:
                    for event in events:
                        res_suspicious.add_line(f"{event}: {self.list_first_x(events[event])}")
                if actions is not None:
                    for action in actions:
                        res_suspicious.add_line(f"{action}: {self.list_first_x(actions[action])}")
                if vulns is not None:
                    for vuln in vulns:
                        if vuln in vulnsDict:
                            temp = [vuln, ' (']
                            for vuln_cve in vulnsDict[vuln]:
                                if len(temp) != 2:
                                    temp.append(',')
                                vuln_cve = "".join(vuln_cve) if isinstance(vuln_cve, list) else vuln_cve
                                temp.append(vuln_cve)
                                cve_found = re.search("CVE-[0-9]{4}-[0-9]{4}", vuln_cve)
                                if cve_found and cve_found.group() not in self.CVE_FALSE_POSITIVES:
                                    vuln_name = cve_found.group()
                                    res_suspicious.add_tag('attribution.exploit', vuln_name)
                                    res_suspicious.add_tag('file.behavior', vuln_name)
                                    res_suspicious.heuristic.add_signature_id(vuln_name, score=500)
                            temp.append('): ')
                            temp.append(str(vulns[vuln]))
                            res_suspicious.add_line(temp)
                        else:
                            res_suspicious.add_line(f"{vuln}: {str(vulns[vuln])}")
                if elements is not None:
                    for element in elements:
                        if element in vulnsDict:
                            temp = [element, ' (']
                            for vuln_cve in vulnsDict[element]:
                                if len(temp) != 2:
                                    temp.append(',')
                                vuln_cve = "".join(vuln_cve) if isinstance(vuln_cve, list) else vuln_cve
                                temp.append(vuln_cve)
                                cve_found = re.search("CVE-[0-9]{4}-[0-9]{4}", vuln_cve)
                                if cve_found and cve_found.group() not in self.CVE_FALSE_POSITIVES:
                                    vuln_name = cve_found.group()
                                    res_suspicious.add_tag('attribution.exploit', vuln_name)
                                    res_suspicious.add_tag('file.behavior', vuln_name)
                                    res_suspicious.heuristic.add_signature_id(vuln_name, score=500)
                            temp.append('): ')
                            temp.append(str(elements[element]))
                            res_suspicious.add_line(temp)
                        else:
                            res_suspicious.add_line(f"\t\t{element}: {str(elements[element])}")

            urls = stats_version['URLs']
            if urls is not None:
                res.add_line("")
                res_url = ResultSection('Found URLs', parent=res)
                for url in urls:
                    res_url.add_line(f"\t\t{url}")
                    res_url.set_heuristic(9)

            buff_heuristic_set = False
            javascript_res = ResultSection("Javascript blocks found")
            for obj in stats_version['Objects'][1]:
                cur_obj = pdf_file.getObject(obj, version)

                if cur_obj.containsJScode:
                    javascript_res.add_line(f"Object [{obj} {version}] contains {len(cur_obj.JSCode)} "
                                            f"block(s) of JavaScript")
                    for js_index, js in enumerate(cur_obj.JSCode):

                        js_code, unescaped_bytes, _, _, _ = analyseJS(js)
                        js_dump += js_code

                        js_res = ResultSection(f"JavaScript Code (block: {js_index})")
                        buffers = analyze_javascript("".join(js_code), unescaped_bytes, js_res, obj, request)
                        if js_res.subsections:
                            javascript_res.add_subsection(js_res)
                            if buffers and not buff_heuristic_set:
                                buff_heuristic_set = True
                                javascript_res.set_heuristic(2)

                elif cur_obj.type == "stream":
                    if cur_obj.isEncodedStream and cur_obj.filter is not None:
                        data = cur_obj.decodedStream
                        encoding = cur_obj.filter.value.replace("[", "").replace("]", "").replace("/",
                                                                                                  "").strip()
                        val = cur_obj.rawValue
                        otype = cur_obj.elements.get("/Type", None)
                        sub_type = cur_obj.elements.get("/Subtype", None)
                        length = cur_obj.elements.get("/Length", None)

                    else:
                        data = cur_obj.rawStream
                        encoding = None
                        val = cur_obj.rawValue
                        otype = cur_obj.elements.get("/Type", None)
                        sub_type = cur_obj.elements.get("/Subtype", None)
                        length = cur_obj.elements.get("/Length", None)

                    if otype:
                        otype = otype.value.replace("/", "").lower()
                    if sub_type:
                        sub_type = sub_type.value.replace("/", "").lower()
                    if length:
                        length = length.value

                    if otype == "embeddedfile":
                        if len(data) > 4096:
                            if encoding is not None:
                                temp_encoding_str = f"_{encoding}"
                            else:
                                temp_encoding_str = ""

                            cur_res = ResultSection(
                                f'Embedded file found ({length} bytes) [obj: {obj} {version}] '
                                f'and dumped for analysis {f"(Type: {otype}) " if otype is not None else ""}'
                                f'{f"(SubType: {sub_type}) " if sub_type is not None else ""}'
                                f'{f"(Encoded with {encoding})" if encoding is not None else ""}'
                            )

                            temp_path_name = f"EmbeddedFile_{obj}{temp_encoding_str}.obj"
                            temp_path = os.path.join(self.working_directory, temp_path_name)
                            with open(temp_path, "wb") as f:
                                if isinstance(data, str):
                                    data = data.encode()
                                f.write(data)
                            f_list.append(temp_path)

                            cur_res.add_line(f"The EmbeddedFile object was saved as {temp_path_name}")
                            res_list.append(cur_res)

                    elif otype not in BANNED_TYPES:
                        cur_res = ResultSection(
                            f'Unknown stream found [obj: {obj} {version}] '
                            f'{f"(Type: {otype}) " if otype is not None else ""}'
                            f'{f"(SubType: {sub_type}) " if sub_type is not None else ""}'
                            f'{f"(Encoded with {encoding})" if encoding is not None else ""}'
                        )
                        for line in val.splitlines():
                            cur_res.add_line(line)

                        emb_res = ResultSection('First 256 bytes', parent=cur_res)
                        first_256 = data[:256]
                        if isinstance(first_256, str):
                            first_256 = first_256.encode()
                        emb_res.set_body(hexdump(first_256), BODY_FORMAT.MEMORY_DUMP)
                        res_list.append(cur_res)
                else:
                    pass
            if javascript_res.subsections:
                file_res.add_section(javascript_res)
        file_res.add_section(res)

        for results in res_list:
            file_res.add_section(results)

        if js_dump:
            js_dump_res = ResultSection('Full JavaScript dump')

            temp_js_dump = "javascript_dump.js"
            temp_js_dump_path = os.path.join(self.working_directory, temp_js_dump)
            try:
                temp_js_dump_bin = "\n\n----\n\n".join(js_dump).encode("utf-8")
            except UnicodeDecodeError:
                temp_js_dump_bin = "\n\n----\n\n".join(js_dump)
            temp_js_dump_sha1 = hashlib.sha1(temp_js_dump_bin).hexdigest()
            with open(temp_js_dump_path, "wb") as f:
                f.write(temp_js_dump_bin)
            f_list.append(temp_js_dump_path)

            js_dump_res.add_line(f"The JavaScript dump was saved as {temp_js_dump}")
            js_dump_res.add_line(f"The SHA-1 for the JavaScript dump is {temp_js_dump_sha1}")

            js_dump_res.add_tag('file.pdf.javascript.sha1', temp_js_dump_sha1)
            file_res.add_section(js_dump_res)

        for filename in f_list:
            request.add_extracted(filename, os.path.basename(filename),
                                  f"Dumped from {os.path.basename(temp_filename)}")
