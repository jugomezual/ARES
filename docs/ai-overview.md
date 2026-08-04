
# AI Assistant Integration – AutoPwn

## Overview

The AutoPwn project integrates a lightweight AI assistant into the web dashboard to enhance user interaction and guidance throughout the offensive security workflow. This assistant is not developed from scratch, but is integrated using an external API (e.g., OpenAI or Mistral) to provide intelligent recommendations and explanations.

## Purpose of the AI Assistant

- Guide the user through the different stages of an attack.
- Explain technical steps such as network scanning, exploiting vulnerabilities, and interpreting results.
- Recommend next actions based on system state (e.g., discovered hosts, open ports).
- Assist in understanding tool outputs like Nmap or Metasploit.
- Help automate common tasks by suggesting commands or strategies.

## Integration Strategy

### Location in Project

- `web-ui/ai-assistant.js` will contain the logic for interacting with the AI API.
- The assistant UI will be embedded in `index.html` (chat box or sidebar).
- Configuration (e.g., API key) will be handled securely via environment variables or a config file.

### Architecture

```
[ User ] → [ Web Dashboard (HTML/JS) ]
                   ↓
         [ AI Assistant UI Component ]
                   ↓
         [ External API (OpenAI, Mistral...) ]
```

### Example Flow

1. **User:** “How do I scan the network?”
2. **Assistant:** “You can use Nmap. Try this command: `nmap -sP 192.168.1.0/24`”
3. **User:** Clicks “Run Scan” button.
4. **Dashboard:** Runs Nmap and shows results.
5. **Assistant:** “This host (192.168.1.42) has port 22 open. Want to attempt an SSH exploit?”

## Considerations

- The AI assistant **does not execute code**; it only makes recommendations.
- API responses are limited to predefined contexts to avoid unsafe suggestions.
- All interactions are logged for audit purposes (optional).

## Benefits

- Improves user experience by reducing manual decision-making.
- Speeds up offensive workflows.
- Makes the tool more accessible to beginners.

---

This assistant is designed as a productivity and learning tool, not as an autonomous attacker.
