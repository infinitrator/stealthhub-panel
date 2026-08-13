# Публикация GitHub Wiki

Исходники документации хранятся в `wiki/` основного репозитория. GitHub
показывает Wiki из отдельного Git-репозитория:

```text
https://github.com/infinitrator/stealthhub-panel.wiki.git
```

Официальная документация GitHub подтверждает, что Wiki можно клонировать как
обычный repository, special files `_Sidebar.md` и `_Footer.md` формируют
навигацию, а опубликованы только изменения default branch:

- [Adding or editing wiki pages](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages)
- [Creating a footer or sidebar](https://docs.github.com/en/communities/documenting-your-project-with-wikis/creating-a-footer-or-sidebar-for-your-wiki)

## Одноразовое включение

1. Откройте repository **Settings -> General -> Features**.
2. Включите **Wikis**.
3. Откройте вкладку **Wiki** и создайте первую страницу `Home`, если GitHub еще
   не создал `<repository>.wiki.git`.
4. В **Settings -> Actions -> General -> Workflow permissions** разрешите
   `Read and write permissions`, если organization policy это допускает.
5. Запустите workflow **Publish Wiki** вручную или отправьте commit, меняющий
   `wiki/**`.

Первичная страница нужна из-за модели GitHub: до нее отдельный wiki repository
может отвечать `Repository not found` даже при включенной feature.

## Автоматическая публикация

Workflow `.github/workflows/wiki.yml`:

- запускается только на `main`, когда изменились `wiki/**` или сам workflow;
- может быть запущен вручную через `workflow_dispatch`;
- сначала запускает `deploy/tests/wiki-check.sh`: проверяет обязательные страницы,
  локальные Markdown-ссылки, code fences и отсутствие удаленной demo-настройки;
- клонирует отдельный wiki repository;
- удаляет из working tree только старые Markdown pages Wiki;
- копирует текущие `.md` из `wiki/`;
- проверяет наличие `Home.md`, `_Sidebar.md`, `_Footer.md`;
- создает commit только при реальном diff;
- выполняет обычный push без force.

Workflow сначала использует optional secret `WIKI_DEPLOY_TOKEN`, затем
`GITHUB_TOKEN`. Отдельный token нужен только если repository/organization не
разрешает встроенному token писать в Wiki.

### Optional fine-grained token

Если push получает HTTP 403:

1. Создайте fine-grained personal access token для этого repository с
   минимально необходимым write access к contents.
2. Добавьте его как Actions secret `WIKI_DEPLOY_TOKEN`.
3. Не помещайте token в YAML, Git URL, issue или log.
4. Повторно запустите **Publish Wiki**.

## Локальная публикация

Автоматический workflow предпочтительнее, но maintainer может синхронизировать
Wiki вручную:

```bash
tmp=$(mktemp -d)
git clone https://github.com/infinitrator/stealthhub-panel.wiki.git "$tmp/wiki"
find "$tmp/wiki" -maxdepth 1 -type f -name '*.md' -delete
cp wiki/*.md "$tmp/wiki/"
git -C "$tmp/wiki" add --all
git -C "$tmp/wiki" commit -m 'docs: publish operator wiki'
git -C "$tmp/wiki" push origin HEAD
rm -rf "$tmp"
```

Перед `find` обязательно проверьте, что `$tmp/wiki` указывает на временный clone.
Команда удаляет только root-level Markdown pages внутри него и не использует
force push.

Локальная проверка без публикации:

```bash
bash deploy/tests/wiki-check.sh
```

## Проверка после публикации

1. Откройте `https://github.com/infinitrator/stealthhub-panel/wiki`.
2. Убедитесь, что Home открывается по умолчанию.
3. Проверьте sidebar и footer на desktop/mobile ширине.
4. Перейдите по каждой внутренней ссылке.
5. Откройте history Wiki и сравните source commit в сообщении публикации.
6. Убедитесь, что в pages нет subscription URLs, passwords, tokens и private
   infrastructure data.

Основной repository остается source of truth. Не редактируйте опубликованные
pages только через GitHub UI: следующий sync заменит изменения содержимым
`wiki/`.
