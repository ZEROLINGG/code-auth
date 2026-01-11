# ===========================================
# 自动化部署脚本：Git + Wrangler Secret + IP 过滤
# ===========================================

# 1️⃣ 设置 Git 提交信息
$commitMessage = Read-Host "请输入本次提交信息"

# 2️⃣ Git 添加、提交、推送
git add .
git commit -m "$commitMessage"
git push

# 3️⃣ 读取 .env 文件并上传到 Cloudflare Worker Secret
$envFile = ".\.env"

if (-Not (Test-Path $envFile)) {
    Write-Host "未找到 .env 文件，退出脚本" -ForegroundColor Red
    exit 1
}

# 创建一个哈希表存储所有 KEY=VALUE
$envVars = @{}

Get-Content $envFile | ForEach-Object {
    # 忽略空行或注释行
    if ($_ -match "^\s*$" -or $_ -match "^\s*#") { return }

    # 分割 KEY=VALUE
    $parts = $_ -split '=', 2
    if ($parts.Count -eq 2) {
        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        $envVars[$key] = $value
    }
}

# 处理 SUPER_ADMIN_IP：分割、过滤掉 0.0.0.0，再合并成逗号分隔字符串
if ($envVars.ContainsKey("SUPER_ADMIN_IP")) {
    $ipList = $envVars["SUPER_ADMIN_IP"] -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "0.0.0.0" }
    $envVars["SUPER_ADMIN_IP"] = $ipList -join ','

    Write-Host "处理后的 SUPER_ADMIN_IP: $($envVars["SUPER_ADMIN_IP"])" -ForegroundColor Green
}

# 上传所有 secret
foreach ($key in $envVars.Keys) {
    Write-Host "尝试删除已有 secret: $key" -ForegroundColor Yellow
    wrangler secret delete $key -f 2>$null   # -f 强制，不存在也不会报错

    # 再上传新的 secret
    $value = $envVars[$key]
    Write-Host "上传 secret: $key" -ForegroundColor Cyan
    $value | wrangler secret put $key
}

