export default {
    async fetch(request, env) {
      // 只接受 POST 請求
      if (request.method !== 'POST') {
        return new Response('請使用 POST 方法', { status: 405 });
      }
  
      // 解析 URL 拿到模型識別碼
      const url = new URL(request.url);
      const parts = url.pathname.split('/').filter(x => x);
  
      const modelMapping = {
        "llama-3-8b": "@cf/meta/llama-3-8b-instruct",
        "deepseek-r1": "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
        "gemma-7b": "@hf/google/gemma-7b-it",
        "phi-2":"@cf/microsoft/phi-2"
      };
  
      const modelKey = parts[0];
      const model = modelMapping[modelKey];
      if (!model) {
        return new Response("未知的模型識別碼: " + modelKey, { status: 400 });
      }
  
      // 從 request body 解析 JSON 拿到 prompt
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return new Response("無效的 JSON", { status: 400 });
      }
  
      const promptInput = body.prompt;
      if (!promptInput) {
        return new Response("錯誤878: 未提供 prompt", { status: 400 });
      }
  
      const response = await env.AI.run(model, { prompt: promptInput });
  
      return Response.json({
        model,
        prompt: promptInput,
        response
      });
    }
  };
  