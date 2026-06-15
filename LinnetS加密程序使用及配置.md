### 加密逻辑

- salt 16 字节、iv 12 字节,都 os.urandom 随机
- PBKDF2-SHA256,600k 次迭代,出 32 字节密钥
- 输出 = salt + iv + 密文 拼一起再 base64,自包含不用另存
- GCM 自带认证标签,密码错或被篡改会直接抛异常
- 每次加密换新 salt → 新密钥,所以随机 IV 不会重用

### 使用
将`LinnetS.py`下载到任意目录，比如`~`

1. 直接Python3运行

2. 快捷方式
在`~/.local/share/applications`创建`LinnetS.desktop`并写入
```text
[Desktop Entry]
Version=1.0
Type=Application
Name=LinnetS
Exec=python3 /home/{username}/LinnetS.py
Path=/home/{username}/
Terminal=false
```
