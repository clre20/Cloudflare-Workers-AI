# Cloudflare-Workers-AI
---
本專案提供一個運行於 Cloudflare Workers 平台上的 AI API。
透過動態 URL 模型映射，本服務能夠根據前端提交的 prompt，調用不同的 AI 模型進行運算並回傳結果。這是一個輕量、擴展性高且具備完善錯誤處理機制的 API 實現。

## 特色

- **僅接受 POST 請求**  
  為確保 API 的一致性與安全性，服務僅允許 POST 請求。
  
- **動態模型映射**  
  從請求 URL 解析並提取模型識別碼，通過映射表選擇對應的 AI 模型。只需更新映射表，即可輕鬆擴展支持新的模型。

- **完善的錯誤處理**  
  包括 HTTP 方法驗證、JSON 解析檢查及必填 `prompt` 欄位檢查，使客戶端能迅速定位錯誤來源。

- **全球低延遲部署**  
  Cloudflare Workers 能夠利用其全球邊緣網絡實現快速、穩定的響應，非常適合即時 AI 推理需求。

## API 使用說明
### URL 格式
調用 API 時，請依據需要調用的 AI 模型，以模型識別碼作為 URL 的第一層路徑參數。
例如，要使用 llama-3-8b 模型，請使用以下 URL：
```
https://example.com/llama-3-8b
```

### 使用方法
- HTTP 方法必須為 POST
- 請求主體必須為 JSON 格式，並包含必填欄位 `prompt`

python範例：
```python
import requests

# 選擇要用的模型，例如 llama-3-8b
model_key = "llama-3-8b"
url = f"https://example.com/{model_key}"

# 準備要送出的 prompt
data = {
    "prompt": "嗨你好，這裡是問題"
}

# 發送 POST 請求
response = requests.post(url, json=data)

# 處理回應
if response.status_code == 200:
    # 將回傳的 JSON 轉換為 Python dictionary
    result = response.json()
    # 只取出 AI 回應部分
    ai_reply_1 = result.get("response")
    ai_reply = ai_reply_1.get("response")
    print("AI 回應：", ai_reply)
else:
    print(f"錯誤 {response.status_code}：{response.text}")
```
