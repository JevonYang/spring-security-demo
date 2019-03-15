# spring-security-demo

## 简介
本例基于SpringSecurity做为权限认证框架，用于控制接口的访问权限。并给出登录的流程、换取token的示例；用token访问需要权限接口的示例。

下面将简述使用方法、原理。

## 使用方法
1. 在application.yml中配置数据库的地址账号密码，执行resources/sql/mydb.sql，写入数据。
数据中只一组账号密码yang/123456
2. 通过`/user/login`端点登录，http://localhost:8080/user/login?username=yang&password=123456 POST方法,换回access_token。
3. 在Header中加入key为`Authorization`，value为上一步获取的access_token，访问需要权限的端点`/demo`，即可返回结果

![login](./src/main/resources/images/login.png)
登录
![visit](./src/main/resources/images/visit.png)
访问有权限端点
![visit](./src/main/resources/images/denied.png)
如果不带Token访问，则被拒绝

## 核心原理
在前后端分离的架构中，权限认证主要包含两个主要的过程：
1. 通过用户名密码换取一个令牌（Token），令牌具有不可修改性，以保证权限的安全。
2. 用户在之后一段时间访问则不用再输入用户名密码，通过Token则可以访问被权限管理限制的接口。

再进一步说，
1. 流程1，是通过用户名密码，从数据库中拿到用户的信息、权限等，并转换成安全框架（这里就是Spring Security）中可识别的身份信息（即Authentication），即视为登录成功，之后将必要的些信息转化为之后一段时间访问的凭证——Token。
2. 流程2，则是将Token解析出来，转成安全框架中可识别身份信息，通过可识别的身份信息，框架再去判断该权限是否可以访问该端点。

可以看到在流程1&2中，前半部分是相同的，都是将凭证（前者为用户名密码，后者为token）转为框架可识别的身份信息，这一步我们视为`认证`流程。后半部分则为，各自认证成功的操作逻辑。流程1生成token较为简单，流程2的后半部分则是安全框架（Spring Security）中权限管理的决策逻辑，即决定是否可以访问的逻辑，这一步我们视为`授权`流程。

下面将从`认证`和`授权`两部分来讲。

## 认证

### SecurityFilterChain 过滤器链
Spring Security采用的是filterChain的设计方式，主要的功能大都由过滤器实现，在启动项目的时候，可以在日志中看到已有的过滤器，可在类似下面的日志里找到`DefaultSecurityFilterChain`，这里面则是SecurityFilterChain
```
2019-03-14 16:43:02.369  INFO 27251 --- [  restartedMain] o.s.s.web.DefaultSecurityFilterChain     : Creating filter chain: org.springframework.security.web.util.matcher.AnyRequestMatcher@1, [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@1d88a93d, org.springframework.security.web.context.SecurityContextPersistenceFilter@184d52d7, org.springframework.security.web.header.HeaderWriterFilter@29d86b1e, org.springframework.security.web.authentication.logout.LogoutFilter@2ce28138, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@320a4f73, com.yang.security.config.JwtAuthorizationTokenFilter@37e7a410, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@534e475b, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@39137df7, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@7c42403f, org.springframework.security.web.session.SessionManagementFilter@1fa2ad2b, org.springframework.security.web.access.ExceptionTranslationFilter@65869e97, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@163d3c44]
```
把各个过滤器抽取出来，我们可以看到是这样，这也是过滤器链的先后顺序。
```
1. WebAsyncManagerIntegrationFilter
2. SecurityContextPersistenceFilter
3. HeaderWriterFilter
4. LogoutFilter
5. **UsernamePasswordAuthenticationFilter**
6. **JwtAuthorizationTokenFilter**
7. RequestCacheAwareFilter
8. SecurityContextHolderAwareRequestFilter
9. SessionManagementFilter
10. ExceptionTranslationFilter
11. FilterSecurityInterceptor
```

这里主要讲一下`UsernamePasswordAuthenticationFilter`及相关的代码，顺带的说一下，我们自己实现`JwtAuthenticationFilter`及周边。

### 示例： 官方Filter——UsernamePasswordAuthenticationFilter

`UsernamePasswordAuthenticationFilter`，顾名思义，是用来处理用户名密码登录的过滤器。所有的Filter核心方法都是`doFilter`，该过滤器的doFilter在其父抽象类中，过滤器只需实现`attemptAuthentication`方法即可。

源码摘录如下（并不是完整的源码，拣选重要部分阐述逻辑）：
```java
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
  
  public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {

	String username = obtainUsername(request);
	String password = obtainPassword(request);
	
	// 根据用户名密码构造AuthenticationToken
	UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
				username, password); 
	
    // 将AuthenticationToken放入AuthenticationProvider进行认证
	return this.getAuthenticationManager().authenticate(authRequest); 
  }
}
```

AuthenticationManager中维护这一个List<AuthenticationProvider>；首先通过`AuthenticationProvider`的`supports`方法检测是否支持该类型的AuthenticationToken；如果支持，则使用`authenticate`认证，认证通过则将`AuthenticationToken`转换成经认证的`Authentication`。
```java
public class ProviderManager implements AuthenticationManager, MessageSourceAware,
		InitializingBean {

	private List<AuthenticationProvider> providers = Collections.emptyList();
	private AuthenticationManager parent;
	private boolean eraseCredentialsAfterAuthentication = true;

    // 遍历Providers
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		
        
		for (AuthenticationProvider provider : getProviders()) {
		    // 如果Authentication不符合，跳过后边步骤，继续循环
			if (!provider.supports(toTest)) {
				continue;
			}

            // 如果Authentication符合，则使用该Provider进行authenticate操作
			result = provider.authenticate(authentication);
            
			if (result != null) {
                copyDetails(authentication, result);
            	break;
			}
		}

		if (result != null) {
			if (eraseCredentialsAfterAuthentication
					&& (result instanceof CredentialsContainer)) {
				((CredentialsContainer) result).eraseCredentials();
			}
			return result;
		}
	}
	
}
```

接下来，说如何将`AuthenticationToken`认证。下面是`DaoAuthenticationProvider`的父抽象类，父类中核心方法就是`authenticate`方法，而子类则只用实现`retrieveUser`方法，该方法调用`UserDetailsService`的`loadUserByUsername`。对于我们用户而言，所要做的就是实现`UserDetailsService`，重写其中的方法，通过`loadUserByUsername`从数据库中拿到用户名和密码，至于后面的验证，事实上都是由`AbstractUserDetailsAuthenticationProvider`已经做好了。

```java

public abstract class AbstractUserDetailsAuthenticationProvider implements
		AuthenticationProvider, InitializingBean, MessageSourceAware {

	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
	  
		String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED": authentication.getName();
        
		// DaoAuthenticationProvider中重载retrieveUser方法，而该方法中的核心方法就是UserDetailsService的loadUserByUsername
		user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
		
		// preCheck
		preAuthenticationChecks.check(user);
		
		additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
		
		// postCheck
		postAuthenticationChecks.check(user);
        
		// 检查成功没有问题，则创建Authentication示例
		return createSuccessAuthentication(principalToReturn, authentication, user);
	}
	
	public boolean supports(Class<?> authentication) {
		return (UsernamePasswordAuthenticationToken.class
				.isAssignableFrom(authentication));
	}
}
```

总结一下：
1. `UsernamePasswordAuthenticationFilter.doFilter`获取用户名密码,生成`UsernamePasswordAuthenticationToken`；
2. 将`UsernamePasswordAuthenticationToken`交给`DaoAuthenticationProvider`验证；
3. `DaoAuthenticationProvider`通过`UserDetailsService.loadUserByUsername`中获取用户名、密码、权限以及其他信息，并进行比对；比对成功，则生成`Authentication`；
4. `UsernamePasswordAuthenticationFilter`将`Authentication`放入`SecurityContextHolder`，认证成功；

齐活！

### 实践：编写自己的Filter——JwtAuthenticationFilter

流程2的主要功能，解析Token，转换成Spring Security内部可识别的身份信息Authentication，并放入上下文中，这一步则是通过JwtAuthenticationFilter来完成，其原理与UsernamePasswordAuthenticationFilter并无二致，我们简单来看一下，当做一个小小的实践练习。

首先编写JwtAuthorizationTokenFilter。我们直接扩展了`AbstractAuthenticationProcessingFilter`这个抽象类,因为想使用其`requiresAuthentication`方法判断访问端点是否需要经过该过滤器；于此同时我们需要实现一个`RequestMatch`匹配访问信息，具体实现按下不表，可以参考代码中`SkipUrlMatcher`实现自己的业务逻辑。

接下来，我们将获取的`access_token`解析，转化成`UserDetails`，代码中Step1中的User即为其具体实现。我们知道，jwt事实上是加密的，只有通过我们自己的秘钥解析才能验证成功，获取内部信息。事实上在这一步骤，我们已经验证了信息的真实性、可用性（Step1），就直接生成`JwtAuthenticationToken`（Step2），这里的authentication已经经过验证，放入`AuthenticationManager.authenticate`过程得到框架可识别的认证信息`Authentication`。将已认证身份信息放入上下文，认证过程完成。

```java
public class JwtAuthorizationTokenFilter extends AbstractAuthenticationProcessingFilter {

  public JwtAuthorizationTokenFilter(RequestMatcher matcher) {
    super(matcher);
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws ServletException, IOException {

    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    HttpServletResponse httpServletResponse = (HttpServletResponse) response;
    
    // Step0. 首先判断访问的端点是否需要经过该过滤器
    if (!requiresAuthentication(httpServletRequest, httpServletResponse)) {
      filterChain.doFilter(httpServletRequest, httpServletResponse);
      return;
    }
    String token = httpServletRequest.getHeader("Authorization");

    // Step1. 将token转换成UserDetails(这里的User是自己写的UserDetail的实现)
    User user = JwtUtil.accessToken2User(token.substring(7));

    // Step2. 将UserDetails转换成Authentication，这里的JwtAuthenticationToken即为Authentication的实现，
    // 一般而言，将UserDetails放入Authentication的principle中,之后如果需要可通过Authentication.getPrinciple的方法把UserDetails取出来
    JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(user, token, user.getAuthorities());

    // Step3. 这一步将AuthenticationToken交由AuthenticationProvider处理，转换成Authentication
    final Authentication authentication = getAuthenticationManager().authenticate(authenticationToken);

    // Step4. 将得到的Authentication实例放入Holder，则认证完成
    SecurityContextHolder.getContext().setAuthentication(authentication);

    // Step5. 进入之后的过滤器处理
    filterChain.doFilter(httpServletRequest, httpServletResponse);
  }
}
```

再来看一下自定义的`JwtAuthenticationProvider`。通过前面的一小节我们知道，`AuthenticationManager.authenticate`过程实际上是通过具体的`AuthenticationProvider`完成，我们前面得到了一个`JwtAuthenticationToken`，我们就专门实现一个处理该实例的`AuthenticationProvider`。在该实现方法里，`authenticate`过程我直接将传入的`authentication`（实例为`jwtAuthenticationToken`）直接返回，是因为Jwt解析过程需要对JWT进行解密、验证，所以我们传入的`JwtAuthenticationToken`已经是验证过的，故在这里没做过多的处理。

```java
public class JwtAuthenticationProvider implements AuthenticationProvider {

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    return authentication;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
  }
}
```
总结一下我们干了什么：
1. 实现一个自定义`AuthorizationTokenFilter`，实现`doFilter`方法，该方法则是认证的整个过程。
2. 获取请求信息（这一节获取的信息是JWT，上一节获取的是用户名密码），将这些信息生成一个`AuthenticationToken`（这一节生成的JwtAuthenticationToken，上一节是UsernamePasswordToken）
3. 将`AuthenticationToken`交给`AuthenticationProvider`验证，在`supports`方法中验证是否支持该类型的`AuthenticationToken`，在`authenticate`方法中完成验证的过程。
4. 将认证后的`Authentication`实例放入安全上下文`SecurityContextHolder`，认证过程全部完成。

## 授权


## 链接
[spring-security-demo](https://github.com/JevonYang/spring-security-demo "spring-security-demo")