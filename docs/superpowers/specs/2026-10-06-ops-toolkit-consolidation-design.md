# Portable Ops Toolkit Consolidation Design

## 1. 目的與範圍 (Purpose & Scope)
將散落於家目錄的維運腳本與虛擬機狀態檢測腳本，收斂至 `~/scripts` 倉庫中進行統一管理。
此專案旨在實現「跨 VM 隨取即用」的 Portable Ops Toolkit，確保未來在新虛擬機上只需透過 Git Clone 與安裝腳本，即可快速佈署所有檢測工具，並全域執行。

## 2. 檔案遷移與收斂 (File Migration)
- **資安檢測腳本**：
  - 將家目錄英文版腳本 `~/security-port-audit.sh` 移入倉庫，並更名為 `~/scripts/bin/port_audit.sh`。
  - 刪除舊版中文腳本 `~/scripts/bin/security-port-audit.sh`。


## 3. 全域環境安裝腳本 (Install Script)
- 於 `~/scripts/install.sh` 建立安裝自動化程式碼。
- **功能包含**：
  1. 移除舊有失效連結：如 `/usr/local/bin/security-audit`。
  2. 自動將 `~/scripts/bin/` 內的所有 `.sh` 腳本（去除 `.sh` 副檔名後）建立軟連結 (symlink) 至 `/usr/local/bin/`。
  3. 為 `bin/` 內的腳本賦予可執行權限 (`chmod +x`)。
- **預期效果**：
  使用者能在終端機直接輸入 `port_audit` 即可執行腳本。

## 4. 版本控制與備份 (Version Control)
- 遷移、新增腳本與建立 `install.sh` 完成後，所有異動均會透過 Git commit 記錄至 `~/scripts`，確保配置可被追溯與跨主機發布。
