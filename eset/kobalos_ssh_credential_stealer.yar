
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These YARA rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2020, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

rule kobalos_ssh_credential_stealer {
    meta:
        description = "Kobalos SSH credential stealer seen in OpenSSH client"
        author = "Marc-Etienne M.Léveillé"
        date = "2020-11-02"
        reference = "http://www.welivesecurity.com"
        reference2 = "https://www.welivesecurity.com/wp-content/uploads/2021/01/ESET_Kobalos.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

    condition:
        any of them
}

