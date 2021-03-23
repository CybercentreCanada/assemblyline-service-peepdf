""" PeePDF service """

import gc
import hashlib
import json
import os
import re
from base64 import b64decode

from assemblyline.common.hexdump import hexdump
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic
from peepdf.ext.peepdf.JSAnalysis import analyseJS, unescape
from peepdf.ext.peepdf.PDFCore import PDFParser, vulnsDict

BANNED_TYPES = ["xref", "objstm", "xobject", "metadata", "3d", "pattern", None]


def validate_non_humanreadable_buff(data: str, buff_min_size: int=256, whitespace_ratio: float=0.10) -> bool:
    """ Checks if a buffer is not human readable using the porportion of whitespace

    data: the buffer
    buff_min_size: minimum buffer size for the test to be meaningful
    whitespace_ratio: ratio of whitespace to non-whitespace characters

    returns: if the buffer size is appropriate and contains less whitespace than whitespace_ratio
    """
    ws_count = data.count(" ")
    ws_count += data.count("%20") * 3
    return len(data) >= buff_min_size and ws_count / len(data) < whitespace_ratio

def check_for_function(function: str, data: str) -> bool:
    """ Checks for a function in javascript code

    function: the name of the function
    data: the javascript code

    returns: Whether the code contains the function
    """
    return re.search(f'[^a-zA-Z]{function}[^a-zA-Z]', data)


# noinspection PyGlobalUndefined
class PeePDF(ServiceBase):
    """ PeePDF service """
    CVE_FALSE_POSITIVES = ["CVE-2009-0658", "CVE-2010-0188"]

    def __init__(self, config=None):
        super().__init__(config)
        self.max_pdf_size = self.config.get('max_pdf_size', 3000000)

    def extract(self, data: bytes, filename: str, request,
            description="Dumped from {os.path.basename(request.file_path)}"):
        """ Extract data as filename in the current working directory and add to request """
        file_path = os.path.join(self.working_directory, filename)
        with open(file_path, 'wb') as f:
            f.write(data)
        request.add_extracted(file_path, filename, description)

    def find_xdp_embedded(self, filename, cbin, request):
        """ Find and report embedded XDP sections in PDF """
        file_res = request.result
        if b'<pdf' in cbin and b'<document>' in cbin and b'<chunk>' in cbin:
            chunks = cbin.split(b'<chunk>')

            chunk_number = 0
            leftover = b''
            for chunk in chunks:
                if b'</chunk>' not in chunk:
                    leftover += chunk.replace(b'<document>', b'') \
                                     .replace(b'<pdf xmlns="http://ns.adobe.com/xdp/pdf/">', b'')
                    continue

                chunk_number += 1

                un_b64 = None
                # noinspection PyBroadException
                try:
                    un_b64 = b64decode(chunk.split(b'</chunk>')[0])
                except Exception:
                    self.log.error("Found <pdf>, <document> and <chunk> tags inside an xdp file but could not "
                                   "un-base64 the content.")

                if un_b64:
                    self.extract(un_b64, f'xdp_{chunk_number}.pdf', request, description=f'UnXDP from {filename}')

            if chunk_number > 0:
                res_section = ResultSection(f"Found {chunk_number} Embedded PDF (in XDP)", heuristic=Heuristic(1))
                res_section.add_tag('file.behavior', "Embedded PDF (in XDP)")
                file_res.add_section(res_section)
        return file_res

    def execute(self, request):
        """ Run service """
        request.result = Result()

        # Filter out large documents
        if os.path.getsize(request.file_path) > self.max_pdf_size:
            res = (ResultSection(f"PDF Analysis of the file was skipped because the "
                                 f"file is too big (limit is {(self.max_pdf_size // 1000_000)} MB)."))
            request.result.add_section(res)
            return

        with open(request.file_path, 'rb') as f:
            file_contents = f.read()

        if b'<xdp:xdp' in file_contents:
            filename = os.path.basename(request.file_path)
            self.find_xdp_embedded(filename, file_contents, request)

        # noinspection PyBroadException
        try:
            pdf_parser = PDFParser()
            ret, pdf_file = pdf_parser.parse(request.file_path, True, False, file_contents)
            if ret == 0:
                self.peepdf_analysis(pdf_file, request)
            else:
                self.log.warning(f"Failed to parse file {pdf_file.errors[-1]}")
                res = ResultSection("ERROR: Could not parse file with PeePDF.")
                request.result.add_section(res)
        except Exception as e:
            self.log.error(f"PeePDF encountered an error for file {request.sha256}: str{e}")
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
        """ Finds large buffers in data """
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
    def list_first_x(mylist, size=20):
        """ Truncate list for display """
        add_reminder = len(mylist) > size

        mylist = mylist[:size]
        if add_reminder:
            mylist.append("...")

        return mylist

    def parse_version_stats(self, stats_version: dict) -> dict:
        """ Parse a PDF versions statistics block into display JSON """
        v_json_body = {
            'catalog': stats_version['Catalog'] or "no",
            'info': stats_version['Info'] or "no",
            'objects': self.list_first_x(stats_version['Objects'][1]),
        }

        if stats_version['Compressed Objects']:
            v_json_body['compressed_objects'] = self.list_first_x(stats_version['Compressed Objects'][1])

        if stats_version['Errors']:
            v_json_body['errors'] = self.list_first_x(stats_version['Errors'][1])

        v_json_body['streams'] = self.list_first_x(stats_version['Streams'][1])

        if stats_version['Xref Streams']:
            v_json_body['xref_streams'] = self.list_first_x(stats_version['Xref Streams'][1])

        if stats_version['Object Streams']:
            v_json_body['object_streams'] = self.list_first_x(stats_version['Object Streams'][1])

        if int(stats_version['Streams'][0]) > 0:
            v_json_body['encoded'] = self.list_first_x(stats_version['Encoded'][1])
            if stats_version['Decoding Errors']:
                v_json_body['decoding_errors'] = self.list_first_x(stats_version['Decoding Errors'][1])

        if stats_version['Objects with JS code']:
            v_json_body['objects_with_js_code'] = \
                self.list_first_x(stats_version['Objects with JS code'][1])

        return v_json_body

    def analyze_javascript(self, js_code, unescaped_bytes, js_res, obj, request):
        """ Create section for javascript code blocks """
        buffers = False

        # Check for Eval and Unescape
        has_eval = check_for_function("eval", js_code)
        has_unescape = check_for_function("unescape", js_code)
        if has_eval:
            eval_res = ResultSection("[Suspicious Function] eval()", heuristic=Heuristic(3), parent=js_res)

            eval_res.add_line("This JavaScript block uses eval() function "
                                      "which is often used to launch deobfuscated "
                                      "JavaScript code.")
        if has_unescape:
            unescape_res = ResultSection("[Suspicious Function] unescape()", heuristic=Heuristic(4), parent=js_res)
            unescape_res.add_line("This JavaScript block uses unescape() "
                                      "function. It may be legitimate but it is definitely "
                                      "suspicious since malware often use this to "
                                      "deobfuscate code blocks.")

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
                        self.extract(b64decode(buff.split(";base64,")[1].strip()), temp_path_name, request)
                    except Exception:
                        self.log.error("Found 'data:;base64, ' buffer "
                                       "but failed to base64 decode.")
                        temp_path_name = None

                if temp_path_name is not None:
                    buff_cond = f" and was resubmitted as {temp_path_name}"
                else:
                    buff_cond = ""
                js_res.add_subsection(ResultSection(
                    f"A {len(buff)} bytes buffer was found in the JavaScript "
                    f"block{buff_cond}. Here are the first 256 bytes.",
                    body=hexdump(bytes(buff[:256], "utf-8")),
                    body_format=BODY_FORMAT.MEMORY_DUMP))
                buffers = True

        # Handle unescaped buffers
        for i, buff  in enumerate(set(unescaped_bytes)):
            try:
                buff = buff.decode("hex")
            except Exception:
                pass

            temp_path_name = f"obj{obj}_unescaped_{i}.buff"

            shell_res = ResultSection(f"Unknown unescaped {len(buff)} bytes JavaScript "
                                      f"buffer (id: {i}) was resubmitted as "
                                      f"{temp_path_name}. Here are the first 256 bytes.",
                                      parent=js_res)
            shell_res.set_body(hexdump(buff[:256]), body_format=BODY_FORMAT.MEMORY_DUMP)
            self.extract(buff, temp_path_name, request)
            js_res.add_tag('file.behavior', "Unescaped JavaScript Buffer")
            shell_res.set_heuristic(6)

        return buffers

    def analyze_stream(self, cur_obj, obj_name, version, request):
        """ Analyze PDF streams """
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
                    f'Embedded file found ({length} bytes) [obj: {obj_name} {version}] '
                    f'and dumped for analysis {f"(Type: {otype}) " if otype is not None else ""}'
                    f'{f"(SubType: {sub_type}) " if sub_type is not None else ""}'
                    f'{f"(Encoded with {encoding})" if encoding is not None else ""}'
                )

                temp_path_name = f"EmbeddedFile_{obj_name}{temp_encoding_str}.obj"
                self.extract(data.encode() if isinstance(data, str) else data,
                        temp_path_name, request)
                cur_res.add_line(f"The EmbeddedFile object was saved as {temp_path_name}")
                request.result.add_section(cur_res)

        elif otype not in BANNED_TYPES:
            cur_res = ResultSection(
                f'Unknown stream found [obj: {obj_name} {version}] '
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
            request.result.add_section(cur_res)


    # noinspection PyBroadException,PyUnboundLocalVariable
    def peepdf_analysis(self, pdf_file, request):
        """ Analyze parsed pdf file """
        file_res = request.result
        f_list = []
        js_dump = []

        stats_dict = pdf_file.getStats()

        if ", ".join(stats_dict['Errors']) == "Bad PDF header, %%EOF not found, PDF sections not found, No " \
                                              "indirect objects found in the body":
            # Not a PDF
            return

        json_body = {
                'version': stats_dict['Version'],
                'binary': stats_dict['Binary'],
                'linearized': stats_dict['Linearized'],
                'encrypted': stats_dict['Encrypted'],
                'Encryption Algorithms': [f"{algorithm_info[0]} {str(algorithm_info[1])} bits"
                    for algorithm_info in stats_dict['Encryption Algorithms']],
                'updates': stats_dict['Updates'],
                'objects': stats_dict['Objects'],
                'streams': stats_dict['Streams'],
                'comments': stats_dict['Comments'],
                'errors': ', '.join(stats_dict['Errors'] if stats_dict['Errors'] else 'None')
        }

        res = ResultSection("PDF File Information", body_format=BODY_FORMAT.KEY_VALUE,
                            body=json.dumps(json_body), parent=file_res)

        for version, stats_version in enumerate(stats_dict['Versions']):
            res_version = ResultSection(f"Version {str(version)}", parent=res,
                    body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(self.parse_version_stats(stats_version)))

            actions = stats_version['Actions']
            events = stats_version['Events']
            vulns = stats_version['Vulns']
            elements = stats_version['Elements']
            if events or actions or vulns or elements:
                res_suspicious = ResultSection('Suspicious elements', parent=res_version)
                res_suspicious.set_heuristic(8)
                if events:
                    for event in events:
                        res_suspicious.add_line(f"{event}: {self.list_first_x(events[event])}")
                if actions:
                    for action in actions:
                        res_suspicious.add_line(f"{action}: {self.list_first_x(actions[action])}")
                if vulns:
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
                if elements:
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
            if urls:
                res.add_line("")
                res_url = ResultSection('Found URLs', heuristic=Heuristic(9, frequency=len(urls)), parent=res)
                for url in urls:
                    res_url.add_line(f"\t\t{url}")

            javascript_res = ResultSection("Javascript blocks found")
            for obj in stats_version['Objects'][1]:
                cur_obj = pdf_file.getObject(obj, version)

                if cur_obj.containsJScode:
                    javascript_res.add_line(f"Object [{obj} {version}] contains {len(cur_obj.JSCode)} "
                                            f"block(s) of JavaScript")
                    for js_index, js in enumerate(cur_obj.JSCode):

                        js_code, unescaped_bytes, _, _, _ = analyseJS(js)
                        js_dump += js_code

                        js_res = ResultSection(f"Suspicious JavaScript Code in {obj} (block: {js_index})")
                        buffers = self.analyze_javascript(''.join(js_code), unescaped_bytes, js_res, obj, request)
                        if js_res.subsections:
                            javascript_res.add_subsection(js_res)
                            if buffers and not javascript_res.heuristic:
                                javascript_res.set_heuristic(2)
                            # Extract javascript block
                            js_res.add_tag('file.behaviour', "Suspicious Javascript in PDF")
                            temp_js_outname = f"object{obj}-{version}_{js_index}.js"
                            self.extract(''.join(js_code).encode("utf-8"), temp_js_outname, request)
                            js_res.add_line(f"The JavaScript block was saved as {temp_js_outname}")
                elif cur_obj.type == "stream":
                    self.analyze_stream(cur_obj, obj, version, request)
            if javascript_res.subsections:
                file_res.add_section(javascript_res)

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
                                  f"Dumped from {os.path.basename(request.file_path)}")
