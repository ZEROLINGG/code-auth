/**
 * HTML 模板
 */

export function getAdminPanelHTML(): string {
    return `<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin</title>
    <style>
        :root { --bg: #0f172a; --panel: #1e293b; --text: #e2e8f0; --accent: #38bdf8; --success: #22c55e; --error: #ef4444; }
        * { box-sizing: border-box; }
        body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }
        .container { background: var(--panel); padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); width: 100%; max-width: 500px; text-align: center; }
        h2 { margin-top: 0; color: var(--accent); font-size: 1.5rem; }
        input, button, select { width: 100%; padding: 12px; margin: 8px 0; border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: white; font-size: 1rem; }
        input:focus, select:focus { outline: none; border-color: var(--accent); }
        button { background: var(--accent); color: #000; font-weight: bold; cursor: pointer; border: none; transition: all 0.2s; }
        button:hover:not(:disabled) { opacity: 0.9; transform: translateY(-1px); }
        button:disabled { background: #475569; cursor: not-allowed; }
        .status { font-size: 0.85rem; min-height: 1.5em; margin: 10px 0; padding: 8px; border-radius: 4px; }
        .status.error { background: rgba(239, 68, 68, 0.1); color: var(--error); }
        .status.success { background: rgba(34, 197, 94, 0.1); color: var(--success); }
        .status.info { background: rgba(56, 189, 248, 0.1); color: var(--accent); }
        .code-display { word-break: break-all; background: #000; padding: 15px; border-radius: 8px; border: 1px dashed #64748b; margin-top: 15px; font-size: 0.85rem; text-align: left; position: relative; max-height: 400px; overflow-y: auto; }
        .code-display.hidden { display: none; }
        .copy-btn { position: absolute; top: 5px; right: 5px; width: auto; padding: 5px 10px; font-size: 0.75rem; }
        .loading { display: inline-block; width: 16px; height: 16px; border: 2px solid #fff; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite; margin-right: 8px; vertical-align: middle; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .info-text { font-size: 0.8rem; color: #94a3b8; margin-top: 15px; }
        .code-item { padding: 8px; margin: 4px 0; background: #1e293b; border-radius: 4px; word-break: break-all; font-family: monospace; }
        .form-row { display: flex; gap: 10px; }
        .form-row select { flex: 1; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 注册码生成</h2>
        <form id="genForm" onsubmit="return genCode(event)">
            <div class="form-row">
                <select id="validity">
                    <option value="1800">30 分钟</option>
                    <option value="3600">1 小时</option>
                    <option value="86400" selected>1 天</option>
                    <option value="604800">1 周</option>
                    <option value="2592000">30 天</option>
                </select>
                <select id="quantity">
                    <option value="1" selected>1 个</option>
                    <option value="5">5 个</option>
                    <option value="10">10 个</option>
                    
                  
                    <option value="20">20 个</option>
                    <option value="50">50 个</option>
                </select>
            </div>
            <button type="submit" id="submitBtn">生成注册码</button>
        </form>
        <div id="status" class="status"></div>
        <div id="result" class="code-display hidden">
            <button class="copy-btn" onclick="copyCode()">复制全部</button>
            <div id="codeText"></div>
        </div>
        <p class="info-text">生成的注册码仅可使用一次，请妥善保管。</p>
    </div>
    <script>
        let generatedCodes = [];
        
        function setStatus(message, type) {
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = 'status ' + type;
        }
        
        function setLoading(loading) {
            const btn = document.getElementById('submitBtn');
            if (loading) {
                btn.disabled = true;
                btn.innerHTML = '<span class="loading"></span>生成中...';
            } else {
                btn.disabled = false;
                btn.textContent = '生成注册码';
            }
        }
        
        async function genCode(event) {
            event.preventDefault();
            
            const validity = parseInt(document.getElementById('validity').value);
            const quantity = parseInt(document.getElementById('quantity').value);
            
            setLoading(true);
            setStatus('正在生成注册码...', 'info');
            
            try {
                const response = await fetch('/a/p/i/v/1/gen/reg/code', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ validity_seconds: validity, quantity: quantity })
                });
                
                const data = await response.json();
                
                if (data.status === 'ok' && data.codes) {
                    generatedCodes = data.codes;
                    displayCodes(data.codes);
                    setStatus('成功生成 ' + data.codes.length + ' 个注册码', 'success');
                } else {
                    setStatus(data.message || '生成失败，请重试', 'error');
                    document.getElementById('result').classList.add('hidden');
                }
            } catch (error) {
                console.error('Error:', error);
                setStatus('网络错误，请检查连接后重试', 'error');
                document.getElementById('result').classList.add('hidden');
            } finally {
                setLoading(false);
            }
            return false;
        }
        
        function displayCodes(codes) {
            const codeText = document.getElementById('codeText');
            const result = document.getElementById('result');
            codeText.innerHTML = codes.map((code, index) => 
                '<div class="code-item">' + (index + 1) + '. ' + code + '</div>'
            ).join('');
            result.classList.remove('hidden');
        }
        
        async function copyCode() {
            if (generatedCodes.length === 0) {
                setStatus('没有可复制的注册码', 'error');
                return;
            }
            try {
                await navigator.clipboard.writeText(generatedCodes.join('\\n'));
                setStatus('已复制到剪贴板！', 'success');
            } catch (err) {
                setStatus('复制失败，请手动复制', 'error');
            }
        }
    </script>
</body>
</html>`;
}