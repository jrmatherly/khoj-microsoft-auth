# LM Studio
:::warning[Unsupported]
Khoj does not work with LM Studio anymore. Khoj leverages [json mode](https://platform.openai.com/docs/guides/structured-outputs#json-mode) extensively but LMStudio's API seems to have dropped support for json mode. [1](https://x.com/lmstudio/status/1770135858709975547), [2](https://lmstudio.ai/docs/api/structured-output)
:::

:::info
This is only helpful for self-hosted users. If you're using [Khoj Cloud](https://app.khoj.dev), you're limited to our first-party models.
:::

:::info
Khoj natively supports local LLMs [available on HuggingFace in GGUF format](https://huggingface.co/models?library=gguf). Using an OpenAI API proxy with Khoj maybe useful for ease of setup, trying new models or using commercial LLMs via API.
:::

[LM Studio](https://lmstudio.ai/) is a desktop app to chat with open-source LLMs on your local machine. LM Studio provides a neat interface for folks comfortable with a GUI.

LM Studio can expose an [OpenAI API compatible server](https://lmstudio.ai/docs/local-server). This makes it possible to turn chat models from LM Studio into your personal AI agents with Khoj.

## Setup
1. Install [LM Studio](https://lmstudio.ai/) and download your preferred Chat Model
2. Go to the Server Tab on LM Studio, Select your preferred Chat Model and Click the green Start Server button
3. Create a new [AI Model API](http://localhost:42110/server/admin/database/aimodelapi/add/) on your Khoj admin panel
   - **Name**: `lmstudio`
   - **Api Key**: `any string`
   - **Api Base Url**: `http://localhost:1234/v1/` (default for LMStudio)
4. Create a new [Chat Model](http://localhost:42110/server/admin/database/chatmodel/add) on your Khoj admin panel.
   - **Name**: `llama3.1` (replace with the name of your local model)
   - **Model Type**: `Openai`
   - **Ai Model Api**: *the lmstudio Ai Model Api you created in step 3*
   - **Max prompt size**: `20000` (replace with the max prompt size of your model)
   - **Tokenizer**: *Do not set for OpenAI, mistral, llama3 based models*
5. Go to [your config](http://localhost:42110/settings) and select the model you just created in the chat model dropdown.
