r"""OpenAI 兼容接口的配置、连通测试与流式分析。

配置保存在 %LOCALAPPDATA%\网络工具\config\ai.json，不再使用 exe 旁的 data 目录。
"""
from __future__ import annotations

import json
import os

import requests

from .paths import config_dir

SYSTEM_PROMPT = (
    "你是资深网络运维工程师。请只依据用户提供的工具输出做判断，不要编造未出现的数据。"
    "用中文回答，结构为：【结论】一句话；【依据】列出关键指标或异常证据；"
    "【建议】按优先级给出可执行步骤（最多 5 条）。如果没有异常，明确说明“未发现明显异常”。"
)


def _path():
    return os.path.join(config_dir(), "ai.json")


def _read():
    try:
        with open(_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _valid_url(url):
    return isinstance(url, str) and url.startswith(("http://", "https://"))


def _endpoint(base):
    base = (base or "").strip().rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def public_config():
    cfg = _read()
    return {
        "configured": bool(_valid_url(cfg.get("base_url")) and cfg.get("model") and cfg.get("api_key")),
        "base_url": cfg.get("base_url", ""),
        "model": cfg.get("model", ""),
        "has_key": bool(cfg.get("api_key")),
        "system_prompt": cfg.get("system_prompt") or SYSTEM_PROMPT,
        "temperature": cfg.get("temperature", 0.3),
    }


def save_config(data):
    cfg = _read()
    data = data or {}
    base_url = str(data.get("base_url") or "").strip()
    model = str(data.get("model") or "").strip()
    if not _valid_url(base_url):
        raise ValueError("接口地址需以 http:// 或 https:// 开头")
    if not model:
        raise ValueError("请填写模型名称")
    key = data.get("api_key")
    if isinstance(key, str):
        key = key.strip()
    else:
        key = ""
    if data.get("clear_key"):
        cfg["api_key"] = ""
    elif key:
        cfg["api_key"] = key
    elif not cfg.get("api_key"):
        raise ValueError("请填写 API Key")
    prompt = data.get("system_prompt")
    if isinstance(prompt, str):
        prompt = prompt.strip()
    else:
        prompt = cfg.get("system_prompt") or SYSTEM_PROMPT
    try:
        temp = float(data.get("temperature", cfg.get("temperature", 0.3)))
    except (TypeError, ValueError):
        temp = 0.3
    temp = min(1.5, max(0.0, temp))
    cfg.update({
        "base_url": base_url,
        "model": model,
        "system_prompt": prompt,
        "temperature": temp,
    })
    path = _path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return public_config()


def _headers(cfg):
    return {
        "Authorization": "Bearer " + (cfg.get("api_key") or ""),
        "Content-Type": "application/json",
    }


def _payload(cfg, messages, stream=False, max_tokens=16):
    return {
        "model": cfg.get("model"),
        "messages": messages,
        "stream": stream,
        "temperature": cfg.get("temperature", 0.3),
        "max_tokens": max_tokens,
    }


def _require():
    cfg = _read()
    if not (_valid_url(cfg.get("base_url")) and cfg.get("model") and cfg.get("api_key")):
        raise ValueError("AI 尚未配置，请先打开「AI 设置」填写接口地址、模型和 API Key")
    return cfg


def _error_text(resp):
    try:
        obj = resp.json()
        err = obj.get("error") if isinstance(obj, dict) else None
        if isinstance(err, dict) and err.get("message"):
            return str(err.get("message"))
        return json.dumps(obj, ensure_ascii=False)[:300]
    except ValueError:
        return (resp.text or "").strip()[:300]


def test_connection():
    cfg = _require()
    try:
        r = requests.post(
            _endpoint(cfg.get("base_url")),
            headers=_headers(cfg),
            json=_payload(cfg, [{"role": "user", "content": "只回复 OK 两个字母"}], False, 16),
            timeout=(10, 40),
        )
    except requests.RequestException as e:
        raise RuntimeError("连接失败：" + str(e)) from e
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code}：{_error_text(r)}")
    try:
        reply = r.json()["choices"][0]["message"]["content"]
        reply = str(reply).strip()
    except (ValueError, KeyError, IndexError) as e:
        raise RuntimeError("返回格式不是 OpenAI 兼容格式") from e
    return {"reply": reply[:200], "model": cfg.get("model")}


def analyze_stream(tool, params, result, focus=""):
    cfg = _require()
    result = result if isinstance(result, str) else (json.dumps(result, ensure_ascii=False) if result is not None else "")
    result = result.strip()
    if not result:
        raise ValueError("当前没有可分析的结果，请先运行工具")
    if len(result) > 15000:
        result = result[:15000] + "\n...（结果过长，已截断）"
    params_text = params if isinstance(params, str) else (
        json.dumps(params, ensure_ascii=False) if params else "—"
    )
    ask = f"工具：{tool or '未知'}\n参数：{params_text}\n\n工具输出：\n{result}"
    focus = (focus or "").strip()
    if focus:
        ask += f"\n\n用户重点关注：{focus}\n请围绕该问题做深度分析，先判断证据是否支持，再按排查优先级给出步骤；证据不足时明确说明还需要哪些检查，不要猜测。"
    elif (tool or "") == "诊断":
        ask += "\n\n请做全局深度分析：按严重程度排序异常项，并给出可执行的排查顺序。"
    messages = [
        {"role": "system", "content": cfg.get("system_prompt") or SYSTEM_PROMPT},
        {"role": "user", "content": ask},
    ]
    try:
        r = requests.post(
            _endpoint(cfg.get("base_url")),
            headers=_headers(cfg),
            json=_payload(cfg, messages, True, 1500),
            stream=True,
            timeout=(10, 120),
        )
    except requests.RequestException as e:
        yield {"type": "error", "message": "连接失败：" + str(e)}
        return
    if not r.ok:
        yield {"type": "error", "message": f"HTTP {r.status_code}：{_error_text(r)}"}
        return

    ctype = (r.headers.get("Content-Type") or "").lower()
    got = False
    try:
        if "event-stream" not in ctype:
            try:
                content = r.json()["choices"][0]["message"]["content"]
            except (ValueError, KeyError, IndexError):
                yield {"type": "error", "message": "返回格式不是 OpenAI 兼容格式"}
                return
            if content:
                got = True
                yield {"type": "delta", "text": content}
            yield {"type": "done"}
            return
        for raw in r.iter_lines(decode_unicode=False):
            if not raw:
                continue
            line = raw.decode("utf-8", "replace")
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
            except ValueError:
                continue
            if not isinstance(obj, dict):
                continue
            err = obj.get("error")
            if err:
                msg = err.get("message") if isinstance(err, dict) else str(err)
                yield {"type": "error", "message": "模型返回错误" + ("：" + str(msg) if msg else "")}
                return
            choices = obj.get("choices") or []
            if not choices:
                continue
            delta = (choices[0].get("delta") or {}).get("content") or (
                (choices[0].get("message") or {}).get("content")
            )
            if delta:
                got = True
                yield {"type": "delta", "text": delta}
    except requests.RequestException as e:
        yield {"type": "error", "message": "读取中断：" + str(e)}
        return
    finally:
        try:
            r.close()
        except Exception:
            pass
    if not got:
        yield {"type": "error", "message": "模型没有返回内容，请检查模型名称或额度"}
        return
    yield {"type": "done"}
