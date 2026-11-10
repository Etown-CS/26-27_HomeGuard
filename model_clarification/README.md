# Model Comparison: Llama 3.2 3B vs Foundation-Sec-8B-Instruct

Outputs from running `backend/llm_explain.py` on the same 11 flagged events
from the IoT-DIAD demo flows, once per model per prompt version.

## Versions
- v1: first prompt, label chosen by the model
- v2: label set by the detector, stricter prompt
- v3: removed "Sentence 1/2" labels, kept the next step
- v4: removed protocol, port, and packet size from the prompt

## Timing (v4, 11 events)
- Llama 3.2 3B: 23 seconds
- Foundation-Sec-8B-Instruct: 37 seconds

## Models
- llama: `llama3.2:3b`
- foundation: `dr-ry/foundation-sec-8b-instruct-chat-GGUF` (4-bit, about 4.9 GB)