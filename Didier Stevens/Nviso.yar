/*
  Version 0.0.1 2017/01/09
  Copyright 2017 NVISO

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  https://www.nviso.be

  History:
    2017/01/09: start
*/

import "pe"

rule py2exe
{
  meta:
        author = "Didier Stevens (https://www.nviso.be)"
        description = "Detect PE file produced by py2exe"
  condition:
        for any i in (0 .. pe.number_of_resources - 1):
          (pe.resources[i].type_string == "P\x00Y\x00T\x00H\x00O\x00N\x00S\x00C\x00R\x00I\x00P\x00T\x00")
}

rule ppaction {
meta:
  author = "Nviso labs/Didier Stevens (https://www.nviso.be)"
  reference = "https://blog.nviso.be/2017/06/07/malicious-powerpoint-documents-abusing-mouse-over-actions/amp/"
strings:
  $a = "ppaction" nocase
condition:
  $a
}

rule powershell {
meta:
  author = "Nviso labs/Didier Stevens (https://www.nviso.be)"
  reference = "https://blog.nviso.be/2017/06/07/malicious-powerpoint-documents-abusing-mouse-over-actions/amp/"
strings:
  $a = "powershell" nocase
condition:
  $a
}
