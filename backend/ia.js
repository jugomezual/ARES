// ================================================
// Librería IA — equivalente a ia.php
// Puerto a Node.js de la librería del profesor
// (c) Julio Gómez López - UALTECH - UAL (original PHP)
// ================================================

const fs   = require("fs");
const path = require("path");
const cfg  = require("./ia_config");

const LOG_DIR = path.join(__dirname, "ia_logs");
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });


// ================================================
// FUNCIÓN PRINCIPAL — equivalente a ia_realizar_consulta()
// Manda el prompt a la IA configurada y devuelve el resultado parseado.
// Devuelve el objeto JSON que respondió la IA, o -1 si hubo error.
// ================================================
async function ia_realizar_consulta(prompt, accion) {
  const inicio    = Date.now();
  const fecha_hora = new Date().toISOString().replace("T", " ").slice(0, 19);

  let respuesta_ia;
  let servidor;

  if (cfg.tipo === "gemini") {
    servidor     = "gemini";
    respuesta_ia = await gemini_realizar_consulta(prompt);
  } else if (cfg.tipo === "ollama") {
    const url    = cfg.llama_api_url ?? "";
    servidor     = new URL(url).hostname;
    respuesta_ia = await llama_realizar_consulta_ollama(prompt);
  } else if (cfg.tipo === "openwebui") {
    const url    = cfg.llama_api_url ?? "";
    servidor     = new URL(url).hostname;
    respuesta_ia = await llama_realizar_consulta_openwebui(prompt);
  } else {
    console.error("[ia] Tipo de modelo no reconocido en ia_config.js:", cfg.tipo);
    return -1;
  }

  const { resultado, tokens, respuesta_cruda = "" } = respuesta_ia;
  const tiempo_ejecucion = ((Date.now() - inicio) / 1000).toFixed(3);
  const resultado_log    = (resultado === -1) ? "Error" : "Éxito";

  const resultado_para_log = (resultado === -1 && respuesta_cruda)
    ? `ERROR. Respuesta completa de la IA:\n${respuesta_cruda}`
    : (typeof resultado === "object" ? JSON.stringify(resultado, null, 2) : String(resultado));

  ia_guardar_log_fichero(servidor, accion, prompt, resultado_para_log, cfg.ia_modelo, fecha_hora, tiempo_ejecucion, resultado_log, tokens);

  return resultado;
}


// ================================================
// GEMINI — equivalente a gemini_realizar_consulta()
// ================================================
async function gemini_realizar_consulta(prompt) {
  const tokens = { tokens_prompt: 0, tokens_razonamiento: 0, tokens_respuesta: 0, tokens_total: 0 };

  try {
    const url  = `https://generativelanguage.googleapis.com/v1beta/models/${cfg.ia_modelo}:generateContent`;
    const body = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { responseMimeType: "application/json", temperature: 0.1 },
    };

    const res = await fetch(url, {
      method:  "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": cfg.api_key },
      body:    JSON.stringify(body),
      signal:  AbortSignal.timeout(60000),
    });

    const raw  = await res.text();
    if (!res.ok) {
      console.error(`[ia][gemini] HTTP ${res.status}:`, raw);
      return { resultado: -1, tokens, respuesta_cruda: raw };
    }

    const json = JSON.parse(raw);
    if (json.error) {
      console.error("[ia][gemini] Error API:", json.error.message);
      return { resultado: -1, tokens, respuesta_cruda: raw };
    }

    if (json.usageMetadata) {
      tokens.tokens_prompt      = json.usageMetadata.promptTokenCount      ?? 0;
      tokens.tokens_razonamiento = json.usageMetadata.thoughtsTokenCount   ?? 0;
      tokens.tokens_respuesta   = json.usageMetadata.candidatesTokenCount  ?? 0;
      tokens.tokens_total       = json.usageMetadata.totalTokenCount       ?? 0;
    }

    const texto = json.candidates?.[0]?.content?.parts?.[0]?.text ?? "";
    if (!texto) {
      console.error("[ia][gemini] Respuesta vacía");
      return { resultado: -1, tokens, respuesta_cruda: raw };
    }

    const limpio    = ia_limpiar_json(texto);
    const resultado = JSON.parse(limpio);
    return { resultado, tokens, respuesta_cruda: raw };

  } catch (e) {
    console.error("[ia][gemini] Excepción:", e.message);
    return { resultado: -1, tokens, respuesta_cruda: e.message };
  }
}


// ================================================
// OLLAMA — equivalente a llama_realizar_consulta_ollama()
// ================================================
async function llama_realizar_consulta_ollama(prompt) {
  const tokens = { tokens_prompt: 0, tokens_razonamiento: 0, tokens_respuesta: 0, tokens_total: 0 };

  try {
    const body = {
      model:   cfg.ia_modelo,
      prompt,
      stream:  false,
      format:  "json",
      options: { temperature: 0.2, num_ctx: 8192 },
    };

    const res = await fetch(cfg.llama_api_url, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
      signal:  AbortSignal.timeout(240000), // Ollama puede ser lento, y este servidor recarga el modelo a menudo
    });

    const raw = await res.text();
    if (!res.ok) {
      console.error(`[ia][ollama] HTTP ${res.status}:`, raw);
      return { resultado: -1, tokens, respuesta_cruda: raw };
    }

    const json = JSON.parse(raw);
    if (json.error) {
      console.error("[ia][ollama] Error API:", json.error);
      return { resultado: -1, tokens, respuesta_cruda: raw };
    }

    tokens.tokens_prompt    = json.prompt_eval_count ?? 0;
    tokens.tokens_respuesta = json.eval_count        ?? 0;
    tokens.tokens_total     = tokens.tokens_prompt + tokens.tokens_respuesta;

    const texto = json.response ?? "";
    if (!texto) {
      console.error("[ia][ollama] Respuesta vacía");
      return { resultado: -1, tokens, respuesta_cruda: raw };
    }

    const limpio    = ia_limpiar_json(texto);
    const resultado = JSON.parse(limpio);
    return { resultado, tokens, respuesta_cruda: raw };

  } catch (e) {
    console.error("[ia][ollama] Excepción:", e.message);
    return { resultado: -1, tokens, respuesta_cruda: e.message };
  }
}


// ================================================
// OPENWEBUI — equivalente a llama_realizar_consulta_openwebui()
// Usa formato compatible con OpenAI Chat Completions
// ================================================
async function llama_realizar_consulta_openwebui(prompt) {
  const tokens = { tokens_prompt: 0, tokens_razonamiento: 0, tokens_respuesta: 0, tokens_total: 0 };
  let texto  = "";
  let limpio = "";

  try {
    const body = {
      model:           cfg.ia_modelo,
      messages: [
        { role: "system", content: "You are a JSON-only API. Never use markdown. Never use code blocks. Respond exclusively with raw valid JSON, nothing else. Never use double quotes (\") inside a JSON string value (e.g. when naming a command or keyword) — use single quotes or no quotes instead, since an unescaped double quote breaks JSON parsing." },
        { role: "user",   content: prompt },
      ],
      response_format: { type: "json_object" },
      format:          "json",
      stream:          false,
      max_tokens:      4096,
    };

    const res = await fetch(cfg.llama_api_url, {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${cfg.llama_api_key ?? ""}`,
      },
      body:   JSON.stringify(body),
      signal: AbortSignal.timeout(240000), // subido de 120s: con max_tokens=4096 la generación puede tardar más
    });

    const raw = await res.text();
    if (!res.ok) {
      console.error(`[ia][openwebui] HTTP ${res.status}:`, raw);
      return { resultado: -1, tokens, respuesta_cruda: raw };
    }

    const json = JSON.parse(raw);
    if (json.error) {
      console.error("[ia][openwebui] Error API:", typeof json.error === "object" ? JSON.stringify(json.error) : json.error);
      return { resultado: -1, tokens, respuesta_cruda: raw };
    }

    if (json.usage) {
      tokens.tokens_prompt    = json.usage.prompt_tokens     ?? 0;
      tokens.tokens_respuesta = json.usage.completion_tokens ?? 0;
      tokens.tokens_total     = json.usage.total_tokens      ?? 0;
    }

    texto = json.choices?.[0]?.message?.content ?? "";
    if (!texto) {
      console.error("[ia][openwebui] Respuesta vacía");
      return { resultado: -1, tokens, respuesta_cruda: raw };
    }

    limpio = ia_limpiar_json(texto);
    const resultado = JSON.parse(limpio);
    return { resultado, tokens, respuesta_cruda: raw };

  } catch (e) {
    console.error("[ia][openwebui] Excepción:", e.message);
    const detalle = texto
      ? `${e.message}\n\n--- TEXTO ORIGINAL DEL MODELO ---\n${texto}\n\n--- TRAS ia_limpiar_json ---\n${limpio}`
      : e.message;
    return { resultado: -1, tokens, respuesta_cruda: detalle };
  }
}


// ================================================
// LIMPIEZA DE JSON — equivalente a ia_limpiar_json()
// Extrae y sanea el JSON que devuelve la IA (a veces viene
// envuelto en bloques markdown, con BOM, trailing commas, etc.)
// ================================================
function ia_limpiar_json(str) {
  if (!str) return "";

  // 1. Extraer del bloque ```json ... ``` si existe
  const mdMatch = str.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
  if (mdMatch) str = mdMatch[1];

  // 1.5. Eliminar comentarios estilo JS ("// ...") que algunos modelos meten
  // para "abreviar" una lista larga (p.ej. "// ... repeat similar objects
  // for all discovered hosts") en vez de escribir todos los elementos.
  // JSON no admite comentarios, así que rompen el parseo. Tiene que ir ANTES
  // de eliminar caracteres de control, porque necesita los saltos de línea
  // reales para saber dónde termina el comentario.
  str = ia_eliminar_comentarios_js(str);

  // 2. Eliminar BOM y caracteres de control
  str = str.replace(/^\uFEFF/, "");
  str = str.replace(/[\x00-\x1F\x7F]/g, "");

  // 3. Probar TODOS los "{" del texto como posible inicio del JSON real.
  // Algunos modelos repiten el prompt entero antes o después de la
  // respuesta real (a veces antes, a veces después — no hay un patrón fijo),
  // y ese prompt repetido contiene sus propias llaves/corchetes sueltos
  // (notación de CVEs tipo "[medium]", o el bloque de ejemplo con
  // "CVE-XXXX-XXXXX" del propio prompt). Para cada "{" candidato extraemos
  // el bloque balanceado, le aplicamos las reparaciones (comillas, comas) y
  // comprobamos si parsea. Nos quedamos con el candidato válido MÁS LARGO,
  // porque la respuesta real (con varias entradas reales) casi siempre pesa
  // más que cualquier plantilla de ejemplo suelta que quede repetida.
  const candidatos = [];
  let pos = str.indexOf("{");
  while (pos !== -1) {
    candidatos.push(pos);
    pos = str.indexOf("{", pos + 1);
  }
  if (candidatos.length === 0) {
    const iArr = str.indexOf("[");
    if (iArr === -1) return str.trim();
    candidatos.push(iArr);
  }

  const repararBloque = (bloque) => {
    // 3.5. Reparar comillas internas sin escapar dentro de un valor de string
    // (algunos modelos devuelven "razon": "usa "msfconsole" para..." sin
    // escapar las comillas de "msfconsole", rompiendo el JSON).
    bloque = ia_reparar_comillas_internas(bloque);
    // 4. Eliminar trailing commas ( ,} o ,] )
    bloque = bloque.replace(/,\s*([\]}])/g, "$1");
    // 5. Sanear escapes inválidos
    bloque = bloque.replace(/(?<!\\)\\(?![\\"\/bfnrtu])/g, "\\\\");
    // 6. Cerrar llaves/corchetes que quedaron abiertos por una respuesta truncada
    return ia_cerrar_brackets_faltantes(bloque).trim();
  };

  let mejor = null;
  for (const inicio of candidatos) {
    const bloque = repararBloque(ia_extraer_json_balanceado(str, inicio));
    try {
      JSON.parse(bloque);
      if (!mejor || bloque.length > mejor.length) mejor = bloque;
    } catch { /* candidato no válido, probamos el siguiente */ }
  }

  if (mejor) return mejor;

  // Ningún candidato parseó — devolvemos el primero reparado tal cual para
  // que el error de JSON.parse aguas arriba refleje algo útil en el log.
  return repararBloque(ia_extraer_json_balanceado(str, candidatos[0]));
}

// Cuenta profundidad de { }/[ ] desde "inicio" (respetando strings y escapes)
// y devuelve el primer objeto/array JSON completo y balanceado. Si nunca
// vuelve a profundidad 0 (respuesta truncada), devuelve hasta el final del
// string tal cual, para que ia_cerrar_brackets_faltantes lo cierre después.
function ia_extraer_json_balanceado(str, inicio) {
  let depth = 0;
  let inString = false;
  for (let i = inicio; i < str.length; i++) {
    const c = str[i];
    if (c === "\\" && inString && i + 1 < str.length) { i++; continue; }
    if (c === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (c === "{" || c === "[") depth++;
    else if (c === "}" || c === "]") {
      depth--;
      if (depth === 0) return str.slice(inicio, i + 1).trim();
    }
  }
  return str.slice(inicio).trim();
}

// Recorre el string llevando el estado "¿estamos dentro de un valor de
// string?" y elimina los comentarios "// ..." que aparezcan FUERA de un
// string (dentro de un string, como en una URL "http://...", se dejan tal
// cual). Corta desde el "//" hasta el siguiente salto de línea.
function ia_eliminar_comentarios_js(str) {
  let out = "";
  let inString = false;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === "\\" && inString && i + 1 < str.length) {
      out += c + str[i + 1];
      i++;
      continue;
    }
    if (c === '"') {
      inString = !inString;
      out += c;
      continue;
    }
    if (!inString && c === "/" && str[i + 1] === "/") {
      while (i < str.length && str[i] !== "\n") i++;
      continue;
    }
    out += c;
  }
  return out;
}

// Recorre el string carácter a carácter llevando el estado "¿estamos dentro
// de un valor de string?". Al encontrar una comilla sin escapar mientras
// estamos dentro de un string, solo la trata como cierre real si el
// siguiente carácter no-espacio es uno de : , } ] — si no, es una comilla
// interna (p.ej. "usa "msfconsole" aquí") y la escapa sin cerrar el string.
function ia_reparar_comillas_internas(str) {
  let out = "";
  let inString = false;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === "\\" && i + 1 < str.length) {
      out += c + str[i + 1];
      i++;
      continue;
    }
    if (c === '"') {
      if (!inString) {
        inString = true;
        out += c;
        continue;
      }
      let j = i + 1;
      while (j < str.length && /\s/.test(str[j])) j++;
      const next = str[j];
      if (next === undefined || ":,}]".includes(next)) {
        inString = false;
        out += c;
      } else {
        out += '\\"';
      }
      continue;
    }
    out += c;
  }
  return out;
}

// Recorre el string llevando una pila de "{"/"[" abiertos (ignorando lo que
// hay dentro de strings) y, si al final queda algo sin cerrar — típico de una
// respuesta truncada porque el modelo se quedó sin tokens — añade los cierres
// que falten en el orden correcto (LIFO).
function ia_cerrar_brackets_faltantes(str) {
  let inString = false;
  const stack = [];
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === "\\" && inString) { i++; continue; }
    if (c === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (c === "{" || c === "[") stack.push(c);
    else if (c === "}" || c === "]") stack.pop();
  }
  if (stack.length === 0) return str;
  let cierre = "";
  for (let i = stack.length - 1; i >= 0; i--) {
    cierre += stack[i] === "{" ? "}" : "]";
  }
  return str + cierre;
}


// ================================================
// LOG EN FICHERO — equivalente a ia_guardar_log_fichero()
// ================================================
function ia_guardar_log_fichero(servidor, accion, prompt, resultado, modelo, fecha_hora, tiempo_ejecucion, resultado_log, tokens) {
  const modelo_safe = modelo.replace(/[^A-Za-z0-9_\-]/g, "_");
  const fecha_safe  = fecha_hora.replace(/[: ]/g, "_").slice(0, 16);
  const filename    = `${fecha_safe}_${modelo_safe}_IA.log`;
  const filepath    = path.join(LOG_DIR, filename);

  const entry = [
    "========================================",
    `[FECHA Y HORA]: ${fecha_hora}`,
    `[SERVIDOR]: ${servidor}`,
    `[ACCIÓN]: ${accion}`,
    `[MODELO]: ${modelo}`,
    `[TIEMPO EJECUCIÓN]: ${tiempo_ejecucion} segundos`,
    `[TOKENS PROMPT]: ${tokens?.tokens_prompt ?? 0}`,
    `[TOKENS RAZONAMIENTO]: ${tokens?.tokens_razonamiento ?? 0}`,
    `[TOKENS RESPUESTA]: ${tokens?.tokens_respuesta ?? 0}`,
    `[TOKENS TOTAL]: ${tokens?.tokens_total ?? 0}`,
    `[ESTADO]: ${resultado_log}`,
    "--- PROMPT ---",
    prompt,
    "--- RESULTADO ---",
    resultado,
    "========================================\n",
  ].join("\n");

  fs.appendFileSync(filepath, entry, "utf8");
}


module.exports = { ia_realizar_consulta };
