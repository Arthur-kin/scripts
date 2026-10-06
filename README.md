# Portable Ops Toolkit

跨虛擬機 (VM) 隨取即用的維運與資安檢測腳本庫。
只要 Clone 下來並執行安裝腳本，所有工具就能立刻在全系統呼叫。

## 🚀 快速安裝 (Install)

```bash
git clone git@github.com:Arthur-kin/scripts.git
cd scripts
sudo ./install.sh
```
*(安裝腳本會自動將 `bin/` 內的工具軟連結至 `/usr/local/bin`)*

## 🛠️ 可用工具 (Tools)

* `port-audit`：快速掃描主機 TCP/UDP 外部監聽埠口，進行資安基線與高危險服務暴露分析。

> **💡 開發提示：** 未來若有新的 `.sh` 腳本，只要丟進 `bin/` 資料夾，再執行一次 `sudo ./install.sh` 就能自動全域生效。
