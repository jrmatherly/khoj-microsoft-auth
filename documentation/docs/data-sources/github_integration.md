# Github integration

:::warning[Unmaintained]
The Github integration is not maintained. We are considering deprecating it. It doesn't seem used by many folks and its cumbersome for us to maintain.
:::

The Github integration allows you to index as many repositories as you want. It's currently default configured to index all Markdown/Org/Text files in each repository. For large repositories, this takes a fairly long time, but it works well for smaller projects.

# Configure your settings

1. Go to [https://app.khoj.dev/settings](https://app.khoj.dev/settings) and enter in settings for the data sources you want to index. You'll have to specify the file paths.

## Use the Github plugin

1. Generate a [classic PAT (personal access token)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) from [Github](https://github.com/settings/tokens) with `repo` and `admin:org` scopes at least.
2. Navigate to [https://app.khoj.dev/settings#github](https://app.khoj.dev/settings/content/github) to configure your Github settings. Enter in your PAT, along with details for each repository you want to index.
3. Click `Save`. Go back to the settings page and click `Configure`.
4. Go to [https://app.khoj.dev/](https://app.khoj.dev/) and start searching!
