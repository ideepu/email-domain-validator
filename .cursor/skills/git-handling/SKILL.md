---
name: git-handling
description: Handle git operations for this repo: status, stage, commit,
  branch, push. Use when the user asks to commit, stage changes, create a
  branch, push, fix pre-commit failures, or write a commit message.
---

# Git handling

## When to use

Apply when the user asks to commit, stage, push, create/switch branches,
fix commit hook failures, or write a commit message.

## Create branch

- Stash if any changes and pull the latest master `git pull origin master --rebase`.
- Branch name must follow the format `type/description`.
- The type can be one of
  (feature|fix|docs|refactor).
- Choose the respective `type` from the changes (staged). If none fit, ask.
- Write a appropriate and concise `description` as per the changes

## Before committing

1. **Check status**: `git status` from repo root.
2. **Stage**: `git add <paths>` or `git add -A` (use specific paths when appropriate).
3. **Hooks**: This project uses pre-commit (ruff, bandit, pylint, mypy,
   markdownlint). Fix reported issues.
4. **Never use** `git commit --no-verify`.
5. **Confirmation**: Must prompt the user for confirmation before
   committing the changes.
6. Follow the commit message pattern:
   - Commit message must match:
     `^(feature|fix|docs|refactor)!?: .+`
   - Prefer short, descriptive (e.g. "feature: Add MX/SPF checks").
   - From repo root: `git commit -m "message"` or `git commit` for editor.
   - If hooks block the commit, fix issues (see linting skill).

## Branching and push

- Create/switch branch: `git checkout -b branch-name` or `git switch -c branch-name`.
- Pull and rebase: `git pull origin master --rebase`.
- Resolve conflicts if possible; otherwise abort rebase.
- Push: `git push` or `git push -u origin <branch>` for first push.
