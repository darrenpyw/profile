---
title: Can I have Mythos? We have Mythos at home.
date: 2026-04-17
layout: post
---

There has been a lot of buzz on Anthropic’s *‘too dangerous to release’* Mythos AI model was able to find and exploit a 17-year old bug **Remote code execution in FreeBSD** [CVE-2026-4747](https://red.anthropic.com/2026/mythos-preview/). The model is touted to be able to "fully autonomously" discover and exploit vulnerabilities. As it is too dangerous to release, only select companies like Google, Microsoft etc. got first dibs on trying Mythos.

# The Motivation
Recently I set up a [local llama.cpp instance](https://darrenpyw.github.io/profile/2026/04/01/llama.cpp.html) on a gaming laptop I bought off Carousell years ago. The intention is to learn how LLMs and Agentic AI works without busting my wallet paying for tokens using frontier models. The hardware limitiation means I can only choose models that fits under 6 GB VRAM on my laptop's RTX 3060 GPU.

I plan to use it as a coding agent and a pentest sidekick where I can offload simple tasks to it. One task typically performed in a pentest is a system configuration review or a source code review as part of a white-box penetration test. Following that, for any suspected vulnerability, craft Proof-of-Concept scripts to exploit the vulnerability and demonstrate impact to the system under test. A code repository under review can contain tens to hundreds of source code files and can be very tedious for a human reviewer to go through.

My bright (\**lazy\**) idea is to shove each file to the local LLM and tell it to do a security review. This is not exactly a novel idea as this can already be done using VS Code with Gemini, Copilot, Claude extensions etc. I wrote an asynchronous code review [agent](https://github.com/darrenpyw/LLaMa-playground/blob/master/agents/async_code_review_agent.py) in Python using [ToolAgents](https://github.com/Maximilian-Winter/ToolAgents) that accepts a filename or a directory containing source files and iteratively submit each one for code review. The context is restricted to the current file under review due to VRAM size limiting the input context. It works quite well against a [sample](https://github.com/darrenpyw/LLaMa-playground/tree/master/samples) of vulnerable source files.

This setup is also useful for organizations that do not wish to upload their source files and intellectual properties to be used as LLM training data.

# The Setup

## Security Advisory - CVE-2026-4747

Reading up the [FreeBSD advisory](https://www.freebsd.org/security/advisories/FreeBSD-SA-26:08.rpcsec_gss.asc), the vulnerable code lies in the rpcsec_gss module, specifically the source file /`lib/librpcsec_gss/svc_rpcsec_gss.c`.

I cloned the repo from official FreeBSD Github repository, specifically `release/14.2.0` from Nov 2024. This should contain the vulnerable code before Anthropic unleashed Mythos on it.

```
$ git clone --depth 1 --branch release/14.2.0  https://github.com/freebsd/freebsd-src.git

$ git log
commit c8918d6c7412fce87922e9bd7e4f5c7d7ca96eb7 (grafted, HEAD, tag: release/14.2.0)
Author: Colin Percival <cperciva@FreeBSD.org>
Date:   Fri Nov 29 00:00:00 2024 +0000

    Update in preparation for 14.2-RELEASE
    
    - Bump BRANCH to RELEASE
    - Add the anticipated RELEASE announcement date
    - Set a static __FreeBSD_version
    
    Approved by:    re (implicit)
    Sponsored by:   Amazon
```

## Model selection

The model chosen for this test is Google Deepmind's [Gemma 4 E4B](https://blog.google/innovation-and-ai/technology/developers-tools/gemma-4/) launched on April 2nd 2026 with knowledge cutoff of January 2025. The Q4_K_XL 4-bit quantized model by Unsloth is loaded using llama.cpp from [huggingface](https://huggingface.co/unsloth/gemma-4-E4B-it-GGUF). This model took up 4.7 GB and fits nicely within the 6 GB VRAM limit.


# Unleashing Mythos... mini? Minithos?

Point the code review agent to the target `lib/librpcsec_gss` directory and let it analyze all the source files in the directory.

```
python .\async_code_review_agent.py -d "C:\Users\Pre-Installed User\Documents\github\freebsd-src\lib\librpcsec_gss"
```

The first couple of runs did not catch the stack overflow vulnerability. Looking at the original prompt, I had instructed the agent to analyze the file for *security misconfigurations*. Maybe that is why it just did that and ignore other classes of vulnerabilities. So I improved the prompt to look out for vulnerabilities and misconfigurations, specifically to look for stack buffer overflows in C programs.

```
diff --git a/agents/async_code_review_agent.py b/agents/async_code_review_agent.py
index b12880d..e3b98ad 100644
--- a/agents/async_code_review_agent.py
+++ b/agents/async_code_review_agent.py
@@ -19,7 +19,8 @@ def task(agent, settings, path):
     logging.debug(f"Processing file: {path}")
 
     um = ChatMessage.create_user_message(f"""
-    Analyze the attached file {path} for security misconfigurations.
+    Analyze the attached file {path} for security vulnerabilities and misconfigurations.
+    For C programs, focus on finding stack buffer overflow vulnerabilities.
     The file content is delimited between <FILE_CONTENT_START> and <FILE_CONTENT_END>.
     First, retrieve the current time in the format: %Y-%m-%d_%H-%M.
     Then write the analysis to a file named '<retrieved_timestamp>-<file_analyzed>.md' (replace <retrieved_timestamp> with the actual timestamp, replace <file_analyzed> with the actual filename).
```

With this change, Gemma4 got it in the first try and identified the vulnerable function name in the file `svc_rpcsec_gss.c`. It correctly identified the failure mode of using memcpy to copy data based on the length provided by the caller (oa->oa_length) without performing a bounds check against the size of rpchdr. This tracks with the FreeBSD [patch](https://www.freebsd.org/security/patches/SA-26:08/rpcsec_gss.patch) released to fix this issue.

---

**File Analyzed:** `svc_rpcsec_gss.c`
**Analysis Timestamp:** 2026-04-17_09-19
## Findings

### 1. Stack Buffer Overflow in `svc_rpc_gss_validate` function [Impact - HIGH]

The `svc_rpc_gss_validate` function attempts to reconstruct the RPC header from the credential data (`oa->oa_base`) into a local stack buffer (`rpchdr`). The code uses `memcpy` to copy data based on the length provided by the caller (`oa->oa_length`) without performing a bounds check against the size of `rpchdr`.

**Vulnerability Context:**
The function declares a local buffer `rpchdr` of fixed size:
```c
int32_t			rpchdr[128 / sizeof(int32_t)]; // Size: 16 * sizeof(int32_t) = 64 bytes
...
if (oa->oa_length) {
    memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
    buf += RNDUP(oa->oa_length) / sizeof(int32_t);
}
```
If an attacker sends a malicious RPC credential where `oa->oa_length` is greater than 64 bytes, the `memcpy` call will write beyond the allocated bounds of `rpchdr`, resulting in a stack buffer overflow. This could lead to arbitrary code execution or program crash (denial of service).

**Potential Issue (Overly Large `oa_length`):**
An attacker can craft a credential packet where `oa->oa_length` exceeds 64 bytes, overwriting adjacent stack variables and potentially function return addresses.

**Proof of Concept Exploit Code:**
```
[Attacker crafts an RPC packet where rm_call.cb_cred.oa_length > 64 bytes,
and provides the first 64 bytes to contain a controlled payload designed to
overwrite the return address of svc_rpc_gss_validate.]
```

**Recommendation:**
1. **Input Validation (Critical):** Before performing the `memcpy`, strictly validate that `oa->oa_length` does not exceed the size of the destination buffer (`rpchdr`). The check should be:
    ```c
    #define RPCHDR_MAX_SIZE (128 / sizeof(int32_t) * sizeof(int32_t)) // 64 bytes

    if (oa->oa_length > RPCHDR_MAX_SIZE) {
        log_status("oa_length_exceeded", client->cl_mech, GSS_S_FAILURE, NULL);
        client->cl_state = CLIENT_STALE;
        return (FALSE);
    }
    // Proceed with memcpy only if the length is validated
    ```
2. **Secure Coding Practices:** Whenever handling length-delimited network or external inputs in C, always use the smallest safe size when copying data (e.g., use `snprintf` or `memcpy(dest, src, min(length, buffer_size))`) to ensure bounds are respected.

### 2. Potential Integer Handling Issues in `svc_rpc_gss_nextverf` [Impact - LOW]

The function relies on bitwise operations and shifts to manage sequence numbers. While the logic appears correct for advancing the window, the handling of sequence number calculations involving `uint32_t` and `htonl` should be thoroughly reviewed to ensure there are no subtle overflow conditions when calculating `offset` or manipulating masks, especially if the sequence window size (`SVC_RPC_GSS_SEQWINDOW`) were configurable or larger. Given the fixed small window size (128), this is a low-risk finding but warrants a detailed audit of arithmetic safety.

**Recommendation:**
1. **Code Review:** Conduct a detailed static analysis specifically on the sequence number logic (`svc_rpc_gss_update_seq` and `svc_rpc_gss_nextverf`) to confirm that all arithmetic operations, especially subtractions and additions involving `offset`, are properly safeguarded against unexpected wrapping or overflow behavior on the target architecture.

---

## The missing parts

The agent still requires some work to get it to produce usable exploit codes. However, the analysis it provides serves as a baseline for a pentester to dig deeper to validate the vulnerability and use the information to start a new coding agent session to create a workable exploit code.

To be fully autonomous, Anthropic's model would have to replicate what a pentester would do when validating the vulnerability. It would have to have the following abilities and skills, which I find amazing and scary if it managed to do it without human intervention. Hope to see more information of the attack chain from Anthropic.

1. Knowledge of UNiX / FreeBSD Operating System.
2. Set up a FreeBSD VM instance and user accounts. Configure and expose the vulnerable network rpc service.
3. Understand the network topology where it deployed the FreeBSD instance.
4. Operate port scanning tool to identify open ports where the vulnerable service is running on.
5. Set up a listener for RCE callback.
6. Run exploit code.
7. Check if it works. If not, debug previous steps until it works or give up.

# Cost

![What did it cost?]({{"/assets/images/what_did_it_cost.jpg" | relative_url}}){:width="80%"}

To think that the first step of this exploit can be replicated with a simple prompt on an old gaming laptop from 2021 with RTX 3060 6GB VRAM GPU, and of course an open weight model for free in 2026 is... just amazing!

A total of 15,488 tokens was consumed to analyze the vulnerable file. Here's the cost table from Google Gemini:


### Frontier LLM Cost Comparison (15,488 Tokens)
*Calculated using a 75% input / 25% output distribution (11,616 Input, 3,872 Output).*

| Model Tier | Representative Model | Input Cost (per 1M) | Output Cost (per 1M) | Total Cost |
| :--- | :--- | :--- | :--- | :--- |
| **Ultra-Premium** | Claude Opus 4.6 | $15.00 | $75.00 | **$0.47** |
| **Flagship** | GPT-5.4 | $2.50 | $15.00 | **$0.09** |
| **Mid-Tier** | Claude Sonnet 4.6 | $3.00 | $15.00 | **$0.10** |
| **Value Frontier** | Gemini 3.1 Pro | $1.25 | $5.00 | **$0.03** |
| **Budget King** | DeepSeek V3.2 | $0.27 | $1.10 | **$0.007** |

---
**Calculation Formula:** `Total = ((Input Tokens / 1,000,000) * Input Rate) + ((Output Tokens / 1,000,000) * Output Rate)`