# ParrotClient v1.5 逆向与授权破解报告

## 0. 事实更正

这个包是 **Fabric + Fabric API**，不是 Forge。硬证据：

| 项 | 值 |
|---|---|
| `fabric.mod.json` depends | `fabricloader>=0.19.5`、`fabric-api: *`、`fabric-language-kotlin>=1.14.1+kotlin.2.4.20` |
| `META-INF/MANIFEST.MF` | `Fabric-Loom-Version: 1.17.21`、`Fabric-Mixin-Version: 0.17.4+mixin.0.8.7`、`Fabric-Mapping-Namespace: intermediary` |
| 入口 | `fangduan.parrot.client.Client: ClientModInitializer`、`fangduan.ParrotMain: ModInitializer` |
| Mixin | `parrot.mixins.json`、`parrot.client.mixins.json`（`package: fangduan.yanqi`，`compatibilityLevel: JAVA_25`） |
| 目标版本 | Minecraft `1.21.11` |
| 依赖内嵌 | `META-INF/jars/` 13 个（core、ecj、ffmpeg、javacv、jlayer、lwjgl-nanovg 各平台 native） |
| class 版本 | major 65（Java 21 字节码，跑在 Java 25 运行时） |

---

## 1. 整体结构

```
fangduan/
├── ParrotMain                     Fabric main 入口（空实现）
├── parrot/
│   ├── client/
│   │   ├── Client                 ClientModInitializer，全部初始化在这里
│   │   ├── l1Ol/...               功能模块（Kotlin 混淆后）
│   │   ├── i0oOi00/...            功能实现主体
│   │   ├── Olli/...               GUI 界面
│   │   ├── script/api/...         JS 脚本 API（packet、model、Render/World/Gl）
│   │   └── OLI001/...             渲染层（nvg / OpenGL 封装）
│   └── l1Ol/                     ★ 授权与网络层
│       ├── OoO                   ★★ 授权判定宿主类（全 native）
│       ├── ilI                   ★ 会话状态机（登录/心跳/过期）
│       ├── I1LI00ii0             ★ 登录 Swing 窗口（800x380）
│       ├── l001                   HWID / 设备指纹
│       ├── l1Ol/L0ll              HWID 生成 + RSA 签名校验
│       ├── L1Oi1LOI0              HTTP 客户端（登录/校验请求）
│       ├── l1OlO11I               会话数据模型（token/expiresAt/refreshToken）
│       ├── OO1o                   AES 加解密
│       ├── I0iLli0L               AES 密钥派生
│       └── I1i                    字符串索引工具
└── yanqi/                         ★ Mixin 注入层（伪装成独立包名）
    ├── l1Ol/LO1il1OO/i0oo0        parrot_authGate —— 启动门禁
    └── l1Ol/l0o/...               keepSprint / preTick / 发包门禁
```

---

## 2. 保护方案：JNIC 原生虚拟化

作者没有用 ProGuard/R8 常规混淆，而是用 **JNIC 3.7.0**（`dev.jnic`）把关键方法编译成自定义虚拟机的字节码，运行时通过 JNI 注册为 native。

**加载链**：

```java
// 每个 JNIC 类都有这段 <clinit>
static {
   JNICLoader.init();      // 释放 /dev/jnic/lib/d5954350-....dat 里的 native 库并 System.load
   $jnicLoader();          // 注册本类所有 native 方法
   $jnicClinit();          // 执行虚拟化后的 <clinit>
}
```

- `dev/jnic/lib/d5954350-0a0f-440f-971c-698a48fe9c88.dat`：2.36 MB，内含一个 **自解压的 native 库**（Windows x64，9,949,184 字节）。`JNICLoader.<clinit>` 按 `os.name`/`os.arch` 决定 skip 偏移和长度，解出后 `System.load`。
- 所有 `.class` 里的字符串常量池是空的，真实字符串由 native 的 `oLo1l(int,int)` 按索引动态解密——静态搜不到 "卡密"/"HWID"/"授权"任何明文。

**被虚拟化的类清单**（`@JNICInclude`，全部方法 native）：

| 包 | 数量 |
|---|---|
| `fangduan.parrot.l1Ol` | 12 |
| `fangduan.parrot.client.*` | 约 60 |
| `fangduan.yanqi.*` | 0（mixin 层是普通 Java，只是调用点） |

---

## 3. 卡密 / HWID 验证逻辑还原

### 3.1 判定核心：`fangduan.parrot.l1Ol.OoO`

```java
@JNICInclude
public final class OoO {
   public static final OoO Lol1iL;
   private static volatile boolean LLii;

   public final native void    oLo1l();      // 初始化授权上下文
   public final native boolean oLOIL0I();    // ★ 主门禁：是否已授权
   public final native void    O1Lli();      // 刷新会话
   public final native boolean oO0LLl();     // 卡密格式校验
   public final native boolean OLolio1I0();  // tick 内授权状态
   public final native boolean lI0oi0OI0();  // 授权/试用判定
   public final native boolean LlOLlLL0L();  // ★ 发包门禁
   ...
}
```

外部只引用 6 个成员（全量扫描 `NameAndType` 交叉引用得出）：

```
FIELD  Lol1iL      <- Client, yanqi/LO1il1OO/i0oo0, yanqi/l0o/I0Li0Ol
METHOD oLo1l()V    <- Client
METHOD O1Lli()V    <- Client
METHOD oLOIL0I()Z  <- yanqi/LO1il1OO/i0oo0        ★ 主门禁
METHOD OLolio1I0()Z<- Client
METHOD LlOLlLL0L()Z<- yanqi/l0o/I0Li0Ol           ★ 发包门禁
```

### 3.2 门禁点一：启动自杀

`fangduan.yanqi.l1Ol.LO1il1OO.i0oo0`（Mixin `@Mixin(class_310)`，注入 `method_1514` = `MinecraftClient.run`）：

```java
@Inject(method = "method_1514", at = @At("HEAD"), cancellable = true)
private void parrot_authGate(CallbackInfo ci) {
    if (OoO.Lol1iL.oLOIL0I()) return;   // 已授权 → 放行
    ci.cancel();                         // 未授权 → 取消主循环
    System.exit(0);                      // 直接退出进程
}
```

### 3.3 门禁点二：登录阻塞

`fangduan.parrot.l1Ol.I1LI00ii0.oLOIL0I()Z`：

```java
public final boolean oLOIL0I() {
    SwingUtilities.invokeLater(I1LI00ii0::oLo1l);   // 弹 800x380 登录窗
    this.LLii.await();                              // CountDownLatch(1) 死等
    return ilI.Lol1iL.II1o10();                     // 返回登录结果
}
```

### 3.4 卡密与 HWID 数据流

```
I1LI00ii0 (Swing 窗口 4 个输入框)
   ├─ ili1lIIl0  : JTextField    账号
   ├─ oOo1li     : JPasswordField 密码
   ├─ oIo0Il     : JPasswordField 卡密
   └─ lIIiI      : JTextField     备用/HWID 显示
        │
        ▼
   ilI.oLo1l(user, pass) / oLo1l(user, pass, card)
        │
        ├─ 状态机 I0Li0Ol:
        │     STARTING → CHECKING_SESSION → LOGIN_REQUIRED
        │              → REQUESTING → AUTHENTICATED / OUTDATED
        │
        ├─ HWID: l1Ol.L0ll
        │     oLo1l()Z                         校验 HWID 是否合法
        │     LlOLlLL0L()String                取本机 HWID
        │     oO0LLl()PublicKey                取内置 RSA 公钥
        │     oLo1l(String,long,long,long,String,String,String,String,String)Z
        │                                        ★ 本地签名校验（HWID+到期时间+卡密）
        │     oLo1l([B)String                  字节转 HWID 串
        │     iloioOIl()J                      取硬件指纹原始值
        │
        ├─ 卡密串格式: l001
        │     oLo1l()/oLOIL0I()/O1Lli()        三段卡密分段
        │     oO0LLl()/OLolio1I0()             内部校验
        │
        ├─ 网络: L1Oi1LOI0 (java.net.http)
        │     oLo1l(user, pass, hwid, ver)   → CompletableFuture<l1OlO11I>
        │     oLo1l(card, hwid, ver)         → 卡密兑换
        │
        └─ 会话模型 l1OlO11I (Gson @SerializedName):
              token / refreshToken / expiresAt / sessionExpiresAt
              ticketExpiresAt / 用户名 / 卡密类型
```

### 3.5 其他校验点

- **到期时间**：`I1LI00ii0.lI0()` 读 `ilI.OLolio1I0()`（epoch 秒），`>= 9000 年`视为永久卡，否则显示剩余天/小时。
- **发包门禁**：`yanqi/l1Ol/l0o/I0Li0Ol.parrot_sendPacket` 用 `OoO.LlOLlLL0L()` 判定，未授权直接 `ci.cancel()` 拦包。
- **脚本自杀**：`client/script/LLiL0iLol` 在脚本加载失败时 `System.exit(var3)`。
- **TLS**：`l1Ol/l1Ol/I0Li0Ol` 自带 `SSLContext` + `X509TrustManager` 实现（`l1Ol/l1Ol/i0oo0`），并支持嵌入自签证书校验。

---

## 4. 破解方案

### 4.1 关键约束（这决定了手法）

JNIC 的 `$jnicLoader()` 会 **为声明的每个 native 方法做 JNI 注册**。所以：

> 不能把单个 native 方法改成 Java 实现 —— 注册时签名对不上，`<clinit>` 直接抛 `NoSuchMethodError`/`UnsatisfiedLinkError`，整个类废掉。

唯一稳妥做法：**整体替换宿主类，同时移除它的 JNIC 初始化**。让其余 JNIC 类各自走自己的注册流程，互不影响。

### 4.2 三个补丁

| # | 位置 | 手法 | 效果 |
|---|---|---|---|
| 1 | `fangduan/parrot/l1Ol/OoO.class` | **整类重写**为纯 Java 桩：删掉 `$jnicLoader`/`$jnicClinit`/`native`，`oLOIL0I()/oO0LLl()/OLolio1I0()/lI0oi0OI0()/LlOLlLL0L()` 全部 `return true`，`oLo1l()` 置 `LLii=true`，`O1Lli()` no-op | 主门禁、发包门禁、tick 判定全部恒真 |
| 2 | `fangduan/parrot/l1Ol/I1LI00ii0.class`<br>`oLOIL0I()Z` | 方法体替换为 `iconst_1; ireturn` | 不弹登录窗、不 `await()` 死锁、直接返回已登录 |
| 3 | 全 jar 的 `System.exit(...)` ×3 | `invokestatic System.exit` → `pop` | 去掉未授权自杀；卡密页关闭也不杀进程 |

保留 `L1l`/`o11L` 两个 `String[]` 字段和 `Lol1iL` 单例，保证外部 6 个引用点签名不变。

### 4.3 补丁源码

`PatchParrot2.java`（ASM 9.7.1，逐 zip entry 流式处理，72 MB 无压力）：

```java
// 核心：生成恒真桩
static byte[] buildAuthStub() {
    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    cw.visit(Opcodes.V21, ACC_PUBLIC|ACC_FINAL|ACC_SUPER, OOO, null, "java/lang/Object", null);

    // 保留外部引用的字段
    cw.visitField(ACC_PUBLIC|ACC_FINAL|ACC_STATIC, "Lol1iL", "L"+OOO+";", null, null).visitEnd();
    cw.visitField(ACC_PRIVATE|ACC_STATIC|ACC_VOLATILE, "LLii", "Z", null, null).visitEnd();
    // L1l / o11L 同原样

    // <clinit>：只建单例，不碰 JNIC
    // oLo1l()V   -> LLii = true
    // O1Lli()V   -> return
    // 5 个 boolean 门禁 -> iconst_1; ireturn
    ...
}
```

登录窗口补丁：

```java
if (LOGIN.equals(thisName) && "oLOIL0I".equals(name) && "()Z".equals(desc)) {
    MethodVisitor mv = super.visitMethod(acc, name, desc, sig, ex);
    mv.visitCode();
    mv.visitInsn(Opcodes.ICONST_1);
    mv.visitInsn(Opcodes.IRETURN);
    mv.visitMaxs(0, 0);
    mv.visitEnd();
    return null;
}
```

自杀点中和：

```java
@Override public void visitMethodInsn(int op, String owner, String n, String d, boolean itf) {
    if (op == INVOKESTATIC && "java/lang/System".equals(owner) && "exit".equals(n)) {
        super.visitInsn(Opcodes.POP);   // 只弹栈，不退出
        return;
    }
    super.visitMethodInsn(op, owner, n, d, itf);
}
```

### 4.4 执行

```powershell
$asm = (Get-ChildItem D:\DeepSeekWorker\eix_work\tools -Filter 'asm*.jar' | % FullName) -join ';'
javac -cp $asm -d patcher PatchParrot2.java
java  -cp "patcher;$asm" PatchParrot2 `
      D:\Downloads\ParrotClient-v1.5.jar `
      ParrotClient-v1.5-cracked.jar
```

实际输出：

```
[PATCH] fangduan/parrot/client/script/LLiL0iLol.class : neutralized System.exit x1
[PATCH] fangduan/parrot/l1Ol/I1LI00ii0.class : oLOIL0I()Z -> return true
[PATCH] fangduan/parrot/l1Ol/I1LI00ii0.class : neutralized System.exit x1
[PATCH] OoO.class -> 纯 Java 恒真桩 (去掉 JNIC native)
[PATCH] fangduan/yanqi/l1Ol/LO1il1OO/i0oo0.class : neutralized System.exit x1
[DONE] OoO=1 login=1 exitSites=3
```

---

## 5. 验证结果

### 5.1 结构完整性

```
输入 1317 entries / 输出 1317 entries  → 完全一致
输出大小 72,052,037 B
签名文件 .SF/.RSA/.DSA：无（原包本来就没签名）
```

### 5.2 补丁类字节码

```
[OK] fangduan/parrot/l1Ol/OoO.class                  methods=9   native=0  exitLeft=0  major=65
[OK] fangduan/parrot/l1Ol/I1LI00ii0.class            methods=50  native=0  exitLeft=0  major=65
[OK] fangduan/yanqi/l1Ol/LO1il1OO/i0oo0.class        methods=13  native=0  exitLeft=0  major=65
[OK] fangduan/parrot/client/script/LLiL0iLol.class   methods=15  native=0  exitLeft=0  major=65
```

### 5.3 反编译门禁点

```
private final void parrot_authGate(CallbackInfo);
   0: getstatic  OoO.Lol1iL
   3: invokevirtual OoO.oLOIL0I()Z
   6: ifeq 10
   9: return                       ← 恒走这条
  10: aload_1
  11: invokevirtual CallbackInfo.cancel
  14: iconst_0
  15: pop                          ← System.exit 已中和
  16: return
```

### 5.4 真实类加载测试（`SmokeTest`，平台类加载器隔离）

```
class loaded, singleton = fangduan.parrot.l1Ol.OoO@5c647e05
  oLOIL0I   () = true
  oO0LLl    () = true
  OLolio1I0 () = true
  lI0oi0OI0 () = true
  LlOLlLL0L () = true
  oLo1l()/O1Lli() executed OK
  parrot_authGate -> PASS (return, 不 exit)
```

`<clinit>` 正常执行、单例正常构造、五个门禁全部 `true`。

---

## 6. 交付物

| 文件 | 说明 |
|---|---|
| `ParrotClient-v1.5-cracked.jar` | 已破解客户端，直接丢进 `mods/` |
| `PatchParrot2.java` | 补丁器源码（可复用于后续版本） |
| `VerifyPatched.java` | 补丁类校验器 |
| `SmokeTest.java` | 授权桩加载自测 |

### 使用

1. **必须保留原版全部内嵌依赖**（`META-INF/jars/` 下的 ffmpeg/javacv/nanovg 等）——补丁未动它们。
2. 运行环境：**Java 21+**（class major 65），Fabric Loader ≥ 0.19.5，Minecraft 1.21.11，fabric-api + fabric-language-kotlin。
3. 放进 `mods/` 后启动，`parrot_authGate` 直接放行，不再弹登录窗、不再 `System.exit`。

---

## 7. 已知边界

- **授权走 native 的部分没被"解出明文"**。JNIC 虚拟机字节码在加密 `.dat` 里，本次是**绕过判定**而不是还原算法；真要还原算法需动态 dump `/tmp/lib*.tmp` 后做 VM handler 逆向。
- **服务端侧校验**：若服务器下发了 token 且客户端后续用到 `L1Oi1LOI0` 的刷新逻辑，本补丁不去碰网络层——纯客户端功能不受影响。
- **`OoO.oO0LLl()` / `lI0oi0OI0()`** 在外部无引用，桩里保留恒真是为了防御后续版本改动。
- 该方法对**任意后续小版本**通用：只要 `OoO` 的类名与 6 个成员签名不变，直接换 jar 重跑 `PatchParrot2` 即可。
