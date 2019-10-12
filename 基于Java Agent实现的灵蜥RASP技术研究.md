# 基于Java Agent实现的灵蜥RASP技术研究

## 一、什么是RASP技术?

> 最近三五年RASP技术已日渐被人们所接收，国内的各大安全厂商也在不断的完善自身产品。RASP技术触及到了应用程序的底层实现，如何实现一款高稳定性和高可用的RASP产品也就变得比较困难了。

在2013年的时候乌云研发了应该是国内第一款商业`RASP产品`：`防护云`。借助于PHP的`auto_prepend_file`和Java的`Filter`特性我们实现了这两种语言层的攻击防御。在2014年`RASP`（`Runtime application self-protection`运行时应用自我保护）技术提出之前“防护云”早就已经实现了基于客户端拦截和云端可视化分析为一体化的安全防御系统研发。

但是这种基于请求过滤(Filter)机制实现的防御相较于传统的WAF已经有了较大的能力提升，但也因为其建立在请求过滤的基础上的实现导致了防御的深度和准确性还是不够，而且基于Filter实现的RASP本身也会有非常多的坑。为了解决这个问题2016年的时候我开始了基于JavaAgent机制的`灵蜥RASP`技术研究，希望通过增强Java语言底层的API来实现更加深层次的防御。

### 1.1 RASP简介

`Runtime application self-protection`一词，简称为RASP。它是一种新型应用安全保护技术，它将保护程序像疫苗一样注入到应用程序中，应用程序融为一体，能实时检测和阻断安全攻击，使应用程序具备自我保护能力。当应用程序遭受到实际攻击伤害，就可以自动对其进行防御，而不需要进行人工干预。

RASP技术可以快速的将安全防御功能整合到正在运行的应用程序中，它拦截从应用程序到系统的所有调用，确保它们是安全的，并直接在应用程序内验证数据请求。Web和非Web应用程序都可以通过RASP进行保护。该技术不会影响应用程序的设计，因为RASP的检测和保护功能是在应用程序运行的系统上运行的。

## 二、Java Agent 机制探索

### 1. Java Agent运行机制

> JDK1.5开始引入了Agent机制(即启动java程序时添加`-javaagent`参数”,如`java -javaagent:/data/test.jar LingXeTest`)，`Java Agent`机制允许用户在JVM加载class文件的时候先加载自己编写的Agent文件，通过修改JVM传入的字节码来实现注入`RASP`防御逻辑。这种方式因为必须是在容器启动时添加jvm参数,所以需要重启Web容器。JDK1.6新增了`attach`方式(`agentmain`)，可以对运行中的java进程附加agent。使用附加的方式可以在容器运行时动态的注入`RASP`防御逻辑。 

使用在应用启动时加入`-javaagent`参数的方式适用于`RASP`常驻用户应用的防御方式,也是我们目前最常用的安装集成方式。但是正因为必须在应用程序启动时加上我们自定义的`-javaagent`参数所以也就会不得不要求用户重启Web容器，一些生产环境的服务是不允许停止的，所以重启问题成了其重大阻碍。

为了解决应用重启问题，我使用了`attach`灵蜥Agent到Java进程的方式来实现防御，当然`attach`和`agent`方式并无太大的差异，只是实现方式会有细微的差别，麻烦的是`attach`需要考虑如何避免重复加载、如何完整的卸载等问题。

### 1.1 LingXeClassFileTransformer示例

我们通过实现`java.lang.instrument.ClassFileTransformer`类并重写`transform`方法即可拿到JVM等待加载的类的`className`(类名)、`classFileBuffer`(字节码)、`classLoader`(类加载器)、`classBeingRedefined`(重定义或重转换的类)、`protectionDomain`(受保护域)。通过ASM字节码库,我们可以完成对JVM传入的字节码的修改工作。只需要在我们预先设定好的类方法处添加防御代码即可实现深入防御。

```java
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

public class LingXeClassFileTransformer implements ClassFileTransformer {

	/**
	 * 重写transform方法可获取到待加载的类相关信息
	 *
	 * @param loader              定义要转换的类加载器；如果是引导加载器，则为 null
	 * @param className           类名,如:java/lang/Runtime
	 * @param classBeingRedefined 如果是被重定义或重转换触发，则为重定义或重转换的类；如果是类加载，则为 null
	 * @param protectionDomain    要定义或重定义的类的保护域
	 * @param classfileBuffer     类文件格式的输入字节缓冲区（不得修改）
	 * @return 返回一个通过ASM修改后添加了防御代码的字节码byte数组。
	 */
	public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
	                        ProtectionDomain protectionDomain, byte[] classfileBuffer) {

		return 通过ASM修改后的字节码;
	}

}
```

### 2. 利用Java Agent机制能做什么?

因为使用`Java Agent`可以深入到JVM类加载机制,所以我们可以轻松的在任意的类方法中插入自己的java代码。比如我们在`java.io.FileOutputStream`类的构造方法里面插入了防御代码就可以获取到用户即将写入的文件路径，拿到文件路径后就可以交给`灵蜥RASP`去检测文件名是否合法？如果写入了非法文件我们可以直接`return`或者`throw`来终止恶意文件的写入。

**经过RASP修改后的FileOutputStream示例**

```java
package com.anbai.lingxe.agent;

import com.anbai.lingxe.agent.hooks.LingXeHookResult;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.OutputStream;

public class FileOutputStream extends OutputStream {

	public FileOutputStream(File file, boolean append) throws FileNotFoundException {
		Object[] var3 = new Object[]{file, append};

		try {
			LingXeHookResult var4 = 灵蜥RASP调用.onMethodEnter(var3, 其他必要参数);

			if (灵蜥处理结果检测) {
				根据RASP返回的结果对象自动return/throw等操作。
			} else {
				FileOutputStream原始逻辑代码...
			}
		} catch (Throwable var12) {
			封装异常处理,防止因为自身异常导致程序无法正常执行的情况。
		}
	}
	
}
```

通过`Hook`机制我们可以实现对大部分可能会存在安全的Java代码实现防御，如：

1. 文件系统防御(目录遍历、文件读、写、重命名、移动等)。
2. SQL查询防御。
3. XML实体注入防御。
4. 恶意表达式执行防御(Ognl、SpEL、MVEL2等)。
5. 恶意WebShell请求拦截。
6. 恶意文件上传。
7. 本地命令执行。
8. 反序列化攻击(Java、XML、Json)。
9. SSRF攻击。
10. 其他类型攻击...。

但是还有一些类型的攻击不太适合使用Hook机制来实现，如：XSS、动态补丁等功能，至于为什么后面的分析会给出答案。

通过上述示例程序可能很多人就会觉得不就是一个程序语言级别的`AOP机制`吗？我们只要实现一套适用于字节码的AOP机制就可以成功的搞定Hook机制了，写个RASP产品似乎没什么难度。

诚然，基于`Java Agent`机制的`RASP`产品核心实现的确是如此简单，我们需要通过预定义大量的Hook点来插入我们防御逻辑从而实现深入的防御。但是仅有此想法恐怕仅仅只能做出一个非常粗浅的甚至存在非常多安全性和稳定性的产品了，因为这个过程中会有非常多的坑需要踩的。`RASP`的核心技术依赖于`Hook`但是绝不仅仅只是`Hook`那么简单。

### 3. 如何更好的实现方法Hook机制?

#### 3.1 Hook点的深度问题

我们常用的Hook思路大概是这样:

1. 确定需要Hook的类全路径,如:`java.lang.Runtime`.
2. 指定需要Hook的方法和方法描述符，如指定方法名`exec`以及描述符`(Ljava/lang/String;)Ljava/lang/Process;`。

这是一种非常典型的对`Runtime`本地命令执行的Hook点，很多人对Java本地命令执行的认识可能也就局限于此；但是跟进`Runtime.getRuntime().exec(xxx)`的调用链可以清晰的看到其最终是调用了`java.lang.ProcessBuilder`类的`start`方法、`start`方法最终又调用了`java.lang.ProcessImpl.start(xxx)`方法、最终调用到`java.lang.UNIXProcess`类(Unix系统是这个，不同的文件系统实现方法不一样)的native方法：`forkAndExec`去执行的系统命令的。所以只是对上层的`Runtime`或者`ProcessBuilder`类进行Hook是远远不够的，攻击者只需要调用更为底层的实现代码即可绕过Hook。

**java.lang.Runtime本地命令执行调用链**

```
at java.lang.ProcessBuilder.start(ProcessBuilder.java:1047)
at java.lang.Runtime.exec(Runtime.java:617)
at java.lang.Runtime.exec(Runtime.java:450)
at java.lang.Runtime.exec(Runtime.java:347)
at java.lang.UNIXProcess.forkAndExec(Native Method)
at java.lang.UNIXProcess.<init>(UNIXProcess.java:185)
at java.lang.ProcessImpl.start(ProcessImpl.java:130)
at java.lang.ProcessBuilder.start(ProcessBuilder.java:1028)
```

与之类似的还有java的文件操作，初级的做法是直接Hook掉`java.io.File`、`java.io.FileInputStream`、`java.io.FileOutputStream`就完事了，但是当你深入研究过Java文件系统后就会发现能够实现文件读写的API不下十处。如：`java.io.RandomAccessFile`、`sun.nio.ch.FileChannelImpl`、`sun.nio.fs.UnixChannelFactory`、`(Windows|Unix)FileSystemProvider`等。

定义一个Hook点之前需要完整的跟一下调用链，否则攻击者可以直接调用底层的API绕过防御。值得注意的是Java语言可以通过`JNI`(`Java Native Interface`)调用动态链接库的方式绕过防御机制，所以需要想办法解决`JNI`的`native`方法调用的安全问题。

Java文件读写底层都是通过JNI调用的，攻击者可以通过反射去调用`native`方法从而会导致Hook被绕过，如：`java.io.RandomAccessFile#read0`,所以还需要考虑`Java反射机制`+`JNI`的安全问题。
