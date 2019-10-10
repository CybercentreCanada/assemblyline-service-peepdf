from __future__ import absolute_import

import gc
import hashlib
import os
import re

from base64 import b64decode

from assemblyline.common.hexdump import hexdump
from assemblyline_v4_service.common.result import Result, ResultSection, Heuristic, BODY_FORMAT
from assemblyline_v4_service.common.base import ServiceBase

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

    def __init__(self, config=None):
        super(PeePDF, self).__init__(config)
        self.max_pdf_size = config.get('max_pdf_size', 3000000)

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global analyseJS, PDFParser, vulnsDict, unescape
        from peepdf.JSAnalysis import analyseJS, unescape
        from peepdf.PDFCore import PDFParser, vulnsDict

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def _report_embedded_xdp(self, file_res, chunk_number, binary, leftover):
        res_section = ResultSection([f"Found {chunk_number}", "Embedded PDF (in XDP)"])
        res_section.set_heuristic(1, "AL_PEEPDF_1")
        res_section.add_tag('FILE_SUMMARY', "Embedded PDF (in XDP)", 10, 'IDENTIFICATION')
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
                except:
                    self.log.error("Found <pdf>, <document> and <chunk> tags inside an xdp file but could not "
                                   "un-base64 the content.")

                if un_b64:
                    new_filename = f"xdp_{chunk_number}.pdf"
                    file_path = os.path.join(self.working_directory, new_filename)
                    f = open(file_path, "wb")
                    f.write(un_b64)
                    f.close()
                    request.add_extracted(file_path, f"UnXDP from {filename}")

            if chunk_number > 0:
                self._report_embedded_xdp(file_res, chunk_number, cbin, leftover)

        return file_res

    def execute(self, request):
        self.import_service_deps()
        temp_filename = request.file_path

        # Filter out large documents
        if os.path.getsize(temp_filename) > self.max_pdf_size:
            file_res = Result()
            res = (ResultSection(f"PDF Analysis of the file was skipped because the "
                                                f"file is too big (limit is {(self.max_pdf_size / 1000 / 1000)} MB)."))

            file_res.add_section(res)
            request.result = file_res
            return

        filename = os.path.basename(temp_filename)
        # noinspection PyUnusedLocal
        file_content = ''
        with open(temp_filename, 'rb') as f:
            file_content = f.read()

        if '<xdp:xdp'.encode(encoding='UTF-8') in file_content:
            self.find_xdp_embedded(filename, file_content, request)

        self.peepdf_analysis(temp_filename, file_content, request)

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
                    except:
                        pass
                except:
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
            idx = 0
            for i in temp_eval[:-1]:
                idx += 1
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
            idx = 0
            for i in temp_unesc[:-1]:
                idx += 1
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

        return str(mylist)

    # noinspection PyBroadException,PyUnboundLocalVariable
    def peepdf_analysis(self, temp_filename, file_content, request):
        file_res = Result()
        try:
            res_list = []
            js_stream = []
            f_list = []
            js_dump = []

            pdf_parser = PDFParser()
            ret, pdf_file = pdf_parser.parse(temp_filename, True, False, file_content)
            if ret == 0:
                stats_dict = pdf_file.getStats()

                if ", ".join(stats_dict['Errors']) == "Bad PDF header, %%EOF not found, PDF sections not found, No " \
                                                      "indirect objects found in the body":
                    # Not a PDF
                    return

                res = ResultSection("PDF File information")
                res.add_line('File: ' + stats_dict['File'])
                res.add_line(['MD5: ', stats_dict['MD5']])
                res.add_line(['SHA1: ', stats_dict['SHA1']])
                res.add_line('SHA256: ' + stats_dict['SHA256'])
                res.add_line(['Size: ', stats_dict['Size'], ' bytes'])
                res.add_line('Version: ' + stats_dict['Version'])
                res.add_line('Binary: ' + stats_dict['Binary'])
                res.add_line('Linearized: ' + stats_dict['Linearized'])
                res.add_line('Encrypted: ' + stats_dict['Encrypted'])
                if stats_dict['Encryption Algorithms']:
                    temp = ' ('
                    for algorithmInfo in stats_dict['Encryption Algorithms']:
                        temp += algorithmInfo[0] + ' ' + str(algorithmInfo[1]) + ' bits, '
                    temp = temp[:-2] + ')'
                    res.add_line(temp)
                res.add_line('Updates: ' + stats_dict['Updates'])
                res.add_line('Objects: ' + stats_dict['Objects'])
                res.add_line('Streams: ' + stats_dict['Streams'])
                res.add_line('Comments: ' + stats_dict['Comments'])
                res.add_line('Errors: ' + {True: ", ".join(stats_dict['Errors']),
                                           False: "None"}[len(stats_dict['Errors']) != 0])
                res.add_line("")

                for version in range(len(stats_dict['Versions'])):
                    stats_version = stats_dict['Versions'][version]
                    res_version = ResultSection('Version ' + str(version), parent=res)
                    if stats_version['Catalog'] is not None:
                        res_version.add_line('Catalog: ' + stats_version['Catalog'])
                    else:
                        res_version.add_line('Catalog: ' + 'No')
                    if stats_version['Info'] is not None:
                        res_version.add_line('Info: ' + stats_version['Info'])
                    else:
                        res_version.add_line('Info: ' + 'No')
                    res_version.add_line('Objects (' + stats_version['Objects'][0] + '): ' +
                                         self.list_first_x(stats_version['Objects'][1]))
                    if stats_version['Compressed Objects'] is not None:
                        res_version.add_line('Compressed objects (' + stats_version['Compressed Objects'][0] + '): ' +
                                             self.list_first_x(stats_version['Compressed Objects'][1]))

                    if stats_version['Errors'] is not None:
                        res_version.add_line('Errors (' + stats_version['Errors'][0] + '): ' +
                                             self.list_first_x(stats_version['Errors'][1]))
                    res_version.add_line('Streams (' + stats_version['Streams'][0] + '): ' +
                                         self.list_first_x(stats_version['Streams'][1]))
                    if stats_version['Xref Streams'] is not None:
                        res_version.add_line('Xref streams (' + stats_version['Xref Streams'][0] + '): ' +
                                             self.list_first_x(stats_version['Xref Streams'][1]))
                    if stats_version['Object Streams'] is not None:
                        res_version.add_line('Object streams (' + stats_version['Object Streams'][0] + '): ' +
                                             self.list_first_x(stats_version['Object Streams'][1]))
                    if int(stats_version['Streams'][0]) > 0:
                        res_version.add_line('Encoded (' + stats_version['Encoded'][0] + '): ' +
                                             self.list_first_x(stats_version['Encoded'][1]))
                        if stats_version['Decoding Errors'] is not None:
                            res_version.add_line('Decoding errors (' + stats_version['Decoding Errors'][0] + '): ' +
                                                 self.list_first_x(stats_version['Decoding Errors'][1]))
                    if stats_version['Objects with JS code'] is not None:
                        res_version.add_line('Objects with JS '
                                             'code (' + stats_version['Objects with JS code'][0] + '): ' +
                                             self.list_first_x(stats_version['Objects with JS code'][1]))
                        js_stream.extend(stats_version['Objects with JS code'][1])

                    actions = stats_version['Actions']
                    events = stats_version['Events']
                    vulns = stats_version['Vulns']
                    elements = stats_version['Elements']
                    if events is not None or actions is not None or vulns is not None or elements is not None:
                        res_suspicious = ResultSection('Suspicious elements', parent=res_version)
                        if events is not None:
                            for event in events:
                                res_suspicious.add_line(event + ': ' + self.list_first_x(events[event]))
                                res_suspicious.set_heuristic(8, "AL_PEEPDF_8")
                        if actions is not None:
                            for action in actions:
                                res_suspicious.add_line(action + ': ' + self.list_first_x(actions[action]))
                                res_suspicious.set_heuristic(8, "AL_PEEPDF_8")
                        if vulns is not None:
                            for vuln in vulns:
                                if vuln in vulnsDict:
                                    temp = [vuln, ' (']
                                    for vulnCVE in vulnsDict[vuln]:
                                        if len(temp) != 2:
                                            temp.append(',')
                                        temp.append(vulnCVE)
                                        cve_found = re.search("CVE-[0-9]{4}-[0-9]{4}", vulnCVE)
                                        if cve_found:
                                            res_suspicious.add_tag('EXPLOIT_NAME',
                                                             vulnCVE[cve_found.start():cve_found.end()],
                                                             50,
                                                             usage='IDENTIFICATION')
                                            res_suspicious.add_tag('FILE_SUMMARY',
                                                             vulnCVE[cve_found.start():cve_found.end()],
                                                             50,
                                                             usage='IDENTIFICATION')
                                    temp.append('): ')
                                    temp.append(str(vulns[vuln]))
                                    res_suspicious.add_line(temp)
                                else:
                                    res_suspicious.add_line(vuln + ': ' + str(vulns[vuln]))
                                res_suspicious.set_heuristic(8, "AL_PEEPDF_8")
                        if elements is not None:
                            for element in elements:
                                if element in vulnsDict:
                                    temp = [element, ' (']
                                    for vulnCVE in vulnsDict[element]:
                                        if len(temp) != 2:
                                            temp.append(',')
                                        temp.append(vulnCVE)
                                        cve_found = re.search("CVE-[0-9]{4}-[0-9]{4}", vulnCVE)
                                        if cve_found:
                                            res_suspicious.add_tag('EXPLOIT_NAME',
                                                             vulnCVE[cve_found.start():cve_found.end()],
                                                             50,
                                                             usage='IDENTIFICATION')
                                            res_suspicious.add_tag('FILE_SUMMARY',
                                                             vulnCVE[cve_found.start():cve_found.end()],
                                                             50,
                                                             usage='IDENTIFICATION')
                                    temp.append('): ')
                                    temp.append(str(elements[element]))
                                    res_suspicious.add_line(temp)
                                    res_suspicious.set_heuristic(8, "AL_PEEPDF_8")
                                else:
                                    res_suspicious.add_line('\t\t' + element + ': ' + str(elements[element]))
                                    res_suspicious.set_heuristic(8, "AL_PEEPDF_8")

                    urls = stats_version['URLs']
                    if urls is not None:
                        res.add_line("")
                        res_url = ResultSection('Found URLs', parent=res)
                        for url in urls:
                            res_url.add_line('\t\t' + url)
                            res_url.set_heuristic(9, "AL_PEEPDF_9")

                    for obj in stats_version['Objects'][1]:
                        cur_obj = pdf_file.getObject(obj, version)

                        if cur_obj.containsJScode:
                            cur_res = ResultSection(f"Object [{obj} {version}] contains {len(cur_obj.JSCode)} "
                                                    f"block of Javascript")
                            score_modifier = 0

                            js_idx = 0
                            for js in cur_obj.JSCode:
                                sub_res = ResultSection('Block of JavaScript:', parent=cur_res)
                                js_idx += 1
                                js_score = 0
                                js_code, unescaped_bytes, _, _ = analyseJS(js)

                                js_dump += [x for x in js_code]

                                # Malicious characteristics
                                big_buffs = self.get_big_buffs("".join(js_code))
                                if len(big_buffs) == 1:
                                    js_score += 500 * len(big_buffs)
                                if len(big_buffs) > 0:
                                    js_score += 500 * len(big_buffs)
                                has_eval, has_unescape = self.check_dangerous_func("".join(js_code))
                                if has_unescape:
                                    js_score += 100
                                if has_eval:
                                    js_score += 100

                                js_cmt = ""
                                if has_eval or has_unescape or len(big_buffs) > 0:
                                    score_modifier += js_score
                                    js_cmt = "Suspiciously malicious "
                                    cur_res.add_tag('FILE_SUMMARY', "Suspicious javascript in PDF",
                                                     50, usage='IDENTIFICATION')
                                    sub_res.set_heuristic(7, "AL_PEEPDF_7")
                                js_res = ResultSection(0, f"{js_cmt}Javascript Code (block: {js_idx})",
                                                       parent=sub_res)

                                if js_score > 0:
                                    temp_js_outname = f"object{obj}-{version}_{js_idx}.js"
                                    temp_js_path = os.path.join(self.working_directory, temp_js_outname)
                                    temp_js_bin = "".join(js_code).encode("utf-8")
                                    f = open(temp_js_path, "wb")
                                    f.write(temp_js_bin)
                                    f.close()
                                    f_list.append(temp_js_path)

                                    js_res.add_line(["The JavaScript block was saved as ", temp_js_outname])
                                    if has_eval or has_unescape:
                                        analysis_res = ResultSection("[Suspicious Functions]",
                                                                     parent=js_res)
                                        if has_eval:
                                            analysis_res.add_line("eval: This javascript block uses eval() function"
                                                                  " which is often used to launch deobfuscated"
                                                                  " javascript code.")
                                            analysis_res.set_heuristic(3, "AL_PEEPDF_3")
                                        if has_unescape:
                                            analysis_res.add_line("unescape: This javascript block uses unescape() "
                                                                  "function. It may be legitimate but it is definitely"
                                                                  " suspicious since malware often use this to "
                                                                  "deobfuscate code blocks.")
                                            analysis_res.set_heuristic(3, "AL_PEEPDF_3")

                                    buff_idx = 0
                                    for buff in big_buffs:
                                        buff_idx += 1
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
                                                    f = open(temp_path, "wb")
                                                    f.write(buff)
                                                    f.close()
                                                    f_list.append(temp_path)
                                                except:
                                                    self.log.error("Found 'data:;base64, ' buffer "
                                                                   "but failed to base64 decode.")
                                                    temp_path_name = None

                                            if temp_path_name is not None:
                                                buff_cond = f" and was resubmitted as {temp_path_name}"
                                            else:
                                                buff_cond = ""
                                            buff_res = ResultSection(f"A {len(buff)} bytes buffer was found in the javascript "
                                                          f"block{buff_cond}. Here are the first 256 bytes.",
                                                          parent=js_res, body=hexdump(buff[:256]),
                                                          body_format=BODY_FORMAT.MEMORY_DUMP)
                                            buff_res.set_heuristic(2, "AL_PEEPDF_2")

                                processed_sc = []
                                sc_idx = 0
                                for sc in unescaped_bytes:
                                    if sc not in processed_sc:
                                        sc_idx += 1
                                        processed_sc.append(sc)

                                        try:
                                            sc = sc.decode("hex")
                                        except:
                                            pass

                                        shell_score = 500
                                        temp_path_name = f"obj{obj}_unescaped_{sc_idx}.buff"

                                        shell_res = ResultSection(f"Unknown unescaped {len(sc)} bytes "
                                                                  f"javascript buffer (id: {sc_idx}) was resubmitted as {temp_path_name}. "
                                                                  "Here are the first 256 bytes.",
                                                                  parent=js_res)
                                        shell_res.set_body(hexdump(sc[:256]), BODY_FORMAT.MEMORY_DUMP)

                                        temp_path = os.path.join(self.working_directory, temp_path_name)
                                        f = open(temp_path, "wb")
                                        f.write(sc)
                                        f.close()
                                        f_list.append(temp_path)

                                        cur_res.add_tag('FILE_SUMMARY', "Unescaped Javascript Buffer",
                                                         50,
                                                         usage='IDENTIFICATION')
                                        shell_res.set_heuristic(6, "AL_PEEPDF_6")
                                        score_modifier += shell_score

                            if score_modifier > 0:
                                res_list.append(cur_res)

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
                                    # TODO: we might have to be smarter here.
                                    if otype is not None:
                                        otype_str = f"(Type: {otype})"
                                    else:
                                        otype_str = ""
                                    if sub_type is not None:
                                        sub_type_str = f"(SubType: {sub_type})"
                                    else:
                                        sub_type_str = ""
                                    if encoding is not None:
                                        encoding_str = f"(Encoded with {encoding})"
                                        temp_encoding_str = f"_{encoding}"
                                    else:
                                        encoding_str = ""
                                        temp_encoding_str = ""
                                    cur_res = ResultSection(f'Embedded file found ({length} bytes) [obj: {obj} {version}]'
                                                                           f' and dumped for analysis {otype_str}{sub_type_str}{encoding_str}')

                                    temp_path_name = f"EmbeddedFile_{obj}{temp_encoding_str}.obj"
                                    temp_path = os.path.join(self.working_directory, temp_path_name)
                                    f = open(temp_path, "wb")
                                    f.write(data)
                                    f.close()
                                    f_list.append(temp_path)

                                    cur_res.add_line(["The EmbeddedFile object was saved as ", temp_path_name])
                                    res_list.append(cur_res)

                            elif otype not in BANNED_TYPES:
                                cur_res = ResultSection(f'Unknown stream found [obj: {obj} {version}] {otype_str}{sub_type_str}{encoding_str}')
                                for line in val.splitlines():
                                    cur_res.add_line(line)

                                emb_res = ResultSection('First 256 bytes', parent=cur_res)
                                emb_res.set_body(hexdump(data[:256]), BODY_FORMAT.MEMORY_DUMP)
                                res_list.append(cur_res)
                        else:
                            pass

                file_res.add_section(res)

                for results in res_list:
                    file_res.add_section(results)

                if js_dump:
                    js_dump_res = ResultSection('Full Javascript dump')

                    temp_js_dump = "javascript_dump.js"
                    temp_js_dump_path = os.path.join(self.working_directory, temp_js_dump)
                    try:
                        temp_js_dump_bin = "\n\n----\n\n".join(js_dump).encode("utf-8")
                    except UnicodeDecodeError:
                        temp_js_dump_bin = "\n\n----\n\n".join(js_dump)
                    temp_js_dump_sha1 = hashlib.sha1(temp_js_dump_bin).hexdigest()
                    f = open(temp_js_dump_path, "wb")
                    f.write(temp_js_dump_bin)
                    f.flush()
                    f.close()
                    f_list.append(temp_js_dump_path)

                    js_dump_res.add_line(["The javascript dump was saved as ", temp_js_dump])
                    js_dump_res.add_line(["The sha1 for the javascript dump is ", temp_js_dump_sha1])

                    js_dump_res.add_tag('PDF_JAVASCRIPT_SHA1', temp_js_dump_sha1, 100,
                                     usage='CORRELATION')
                    file_res.add_section(js_dump_res)

                for filename in f_list:
                    request.add_extracted(filename, f"Dumped from {os.path.basename(temp_filename)}")

            else:
                res = ResultSection("ERROR: Could not parse file with peepdf.")
                file_res.add_section(res)
        finally:
            request.result = file_res
            try:
                del pdf_file
            except:
                pass

            try:
                del pdf_parser
            except:
                pass

            gc.collect()
