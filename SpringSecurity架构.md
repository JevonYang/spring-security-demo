# Spring Security架构与实现
如果您已经熟悉如何配置基于应用的命名空间，您可能还希望了解在命名空间配置背后，框架是如何工作的，从而进行二次开发。像大多数软件，Spring Security包含几个常用的核心接口、类以及概念的抽象。在这一部分文档中，我们会学习这些接口、类、概念，以及它们在框架中何如支持认证和权限控制。

## 技术总览
### 1.1运行环境
Spring Security 3.0需要Java 5.0以上的运行环境。如Spring Security的目标——在自由容器中操作——一般，无需多余配置您的Java运行环境。需要说明的是，无需配置JAAS（Java Authentication and Authorization Service）文件或者将Spring Security放入classpath路径。

类似的，如果使用EJB容器或者Servlet容器，无需在任何地方配置任何配置文件，也不需要server类加载器包含Spring Security。所有所需的文件仅需包含在你的应用中。
这种设计给予最大的部署灵活性，你可以简单的将编译后的目标文件（例如jar、war、ear）从一个系统复制到另一个系统直接运行。

### 1.2核心组件（Core Components）
在Spring Security 3.0中， spring-security-core jar被拆分到耦合最低。spring-security-core不再包括任何关于web应用安全、LDAP或命名空间配置。

#### 对象SecurityContextHolder、SecurityContext、Authentication
最基础的对象是SecurityContextHolder，这个对象存了当前security上下文详情,其中包括使用当前应用的的principal细节。默认配置， SecurityContextHolder使用`ThreadLocal`存储这些detail,这意味着同一线程中的方法总是能够获取security上下文，即使security上下文没有明确地传递给这些方法的参数。在当前principal的请求被处理后，ThreadLocal被清除，那么这样使用`ThreadLocal`就是安全的。当然，Spring Security自动的帮助用户处理这些，所以用户无需担心安全问题。

由于部分应用用独特的方式工作的线程之间，一些应用并不是完全适合使用`ThreadLocal`。举个例子，Swing 客户端可能希望所有JVM中的线程使用同样的安全上下文。`SecurityContextHolder`能在启动时配置策略——用户希望上下文如何存储。对于一个独立应用，用户可以使用`SecurityContextHolder.MODE_GLOBAL strategy`。其他应用可能希望安全线程产生大量线程，并认证相同安全身份。这是使用配置`SecurityContextHolder.MODE_INHERITABLETHREADLOCAL`。用户能够通过两种方法改变默认的`SecurityContextHolder.MODE_THREADLOCAL`模式。其一，设置系统属性；其二，在`SecurityContextHolder`中调用静态方法。大多数应用无需改变默认配置，除非你希望这样做，你可以在JavaDoc查看更多关于`SecurityContextHolder`内容。

#### 获取当前用户信息
在`SecurityContextHolder`内部，我们存储当前principal详情与应用交互。Spring Security使用一个`Authentication`对象表示信息。通常用户不必自己创建`Authentication`对象，但是查询`Authentication`对象是经常的事情。用户可以使用下面的代码获取当前认证用户的名字————这些代码可以加入代码任何地方。

```
Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

if (principal instanceof UserDetails) {
String username = ((UserDetails)principal).getUsername();
} else {
String username = principal.toString();
}
```

调用的getContext()返回的对象是`SecurityContext`接口的一个实例。这个对象保存在当前线程中。像我们之前看到的，Spring Security中大多数认证机制返回一个`UserDetial`的实例作为principal。

#### UserDetailsService
关于以上的diamante片段需要说明的是，你能从`Authentication`对象获取一个principal。这个principal只是一个对象。大多是时候，这个对象能够转换成`UserDetails`对象。`UserDetails`是一个Spring Security的核心接口，它能够表示一个principal，但是是从国一个可扩展的且应用限定的方法。把`UserDetail`当做用户数据库和Spring Security中SecurityContextHolder中的适配器。作为用户数据库的表示层，用户常常将UserDetials转化为你自己应用提供的“源对象”，所以你可以调用业务特有的方法（例如getEmail() getEmployeeNumber()等等）。

到现在你可能还在想，我们什么时候提供UserDetial对象？我如何提供这个对象？我曾认为你说的这些问题都是显而易见的，无需写任何示例代码。那么什么我将给出？最简单的答案就是，有个特殊的接口叫UserDetailService。这个接口中唯一一个方法就是接受一个类型为字符串的参数username，并返回UserDetails：`UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;`。这是一个最通用的方法在Spring Security中加载用户信息，并且你会发现在这个方法的使用贯穿整个框架，无论你需要获取用户的什么信息。

对于认证成功，UserDetails用于构造Authentication对象，而Authentication对象则是存在SecurityContextHolder中。好消息是，我们一同了一些列的UserDetailService的实现，包括一个实现使用内存map（InMemoryDaoImpl），另一个则是使用JDBC（JdbcDaoImpl）。大多数用户倾向于写他们自己的实现类，这些实现类通常通过已有的DAO层获取数据，用来表示员工、或者应用中的其他用户。无论UserDetailService返回的是什么，都能够通过上面的代码在SecurityContextHolder中获取。

注：
通常对于UserDetailsService会产生误解，它是一个用于获取用户数据的纯DAO层，并且框架中唯一提供数据给其他组件的功能。特别的，userDetailsService并不认证用户，认证用户的过程是通过AuthenticationManager完成。在许多情况下，如果需要一个自定义的认证过程，直接实现AuthenticationProvider变得更有意义。

GrantedAuthority
除了principal之外，Authentication提供了另外一个重要的方法就是getAuthorities()。这个方法提供了一个数组的GrantedAuthority对象。顾名思义，GrantedAuthority就是一个赋予principal的权限。这样的权限通常是“角色（roles）”，比如说，ROLE_ADMINISTRATOR or ROLE_HR_SUPERVISOR。这些角色是之后再为web权限、方法权限、领域对象权限等配置。

