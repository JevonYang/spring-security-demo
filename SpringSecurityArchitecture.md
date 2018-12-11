8. Architecture and Implementation

Once you are familiar with setting up and running some namespace-configuration based applications, you may wish to develop more of an understanding of how the framework actually works behind the namespace facade. Like most software, Spring Security has certain central interfaces, classes and conceptual abstractions that are commonly used throughout the framework. In this part of the reference guide we will look at some of these and see how they work together to support authentication and access-control within Spring Security.

8.1 Technical Overview
8.1.1 Runtime Environment
Spring Security 3.0 requires a Java 5.0 Runtime Environment or higher. As Spring Security aims to operate in a self-contained manner, there is no need to place any special configuration files into your Java Runtime Environment. In particular, there is no need to configure a special Java Authentication and Authorization Service (JAAS) policy file or place Spring Security into common classpath locations.

Similarly, if you are using an EJB Container or Servlet Container there is no need to put any special configuration files anywhere, nor include Spring Security in a server classloader. All the required files will be contained within your application.

This design offers maximum deployment time flexibility, as you can simply copy your target artifact (be it a JAR, WAR or EAR) from one system to another and it will immediately work.

8.1.2 Core Components

In Spring Security 3.0, the contents of the spring-security-core jar were stripped down to the bare minimum. It no longer contains any code related to web-application security, LDAP or namespace configuration. 

We’ll take a look here at some of the Java types that you’ll find in the core module. 
They represent the building blocks of the framework, so if you ever need to go beyond a simple namespace configuration then it’s important that you understand what they are, even if you don’t actually need to interact with them directly.

`SecurityContextHolder`, `SecurityContext` and `Authentication` Objects

The most fundamental object is SecurityContextHolder. This is where we store details of the present security context of the application, which includes details of the principal currently using the application. By default the SecurityContextHolder uses a `ThreadLocal` to store these details, which means that the security context is always available to methods in the same thread of execution, even if the security context is not explicitly passed around as an argument to those methods.Using a ThreadLocal in this way is quite safe if care is taken to clear the thread after the present principal’s request is processed. Of course, Spring Security takes care of this for you automatically so there is no need to worry about it.


Some applications aren’t entirely suitable for using a `ThreadLocal`, because of the specific way they work with threads. For example, a Swing client might want all threads in a Java Virtual Machine to use the same security context. SecurityContextHolder can be configured with a strategy on startup to specify how you would like the context to be stored. For a standalone application you would use the `SecurityContextHolder.MODE_GLOBAL strategy`. Other applications might want to have threads spawned by the secure thread also assume the same security identity. This is achieved by using `SecurityContextHolder.MODE_INHERITABLETHREADLOCAL`. You can change the mode from the default SecurityContextHolder.MODE_THREADLOCAL in two ways. The first is to set a system property, the second is to call a static method on SecurityContextHolder. Most applications won’t need to change from the default, but if you do, take a look at the JavaDoc for SecurityContextHolder to learn more.

Obtaining information about the current user
Inside the SecurityContextHolder we store details of the principal currently interacting with the application. Spring Security uses an Authentication object to represent this information. You won’t normally need to create an Authentication object yourself, but it is fairly common for users to query the Authentication object. You can use the following code block - from anywhere in your application - to obtain the name of the currently authenticated user, for example:

```
Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

if (principal instanceof UserDetails) {
String username = ((UserDetails)principal).getUsername();
} else {
String username = principal.toString();
}
```

The object returned by the call to getContext() is an instance of the SecurityContext interface. This is the object that is kept in thread-local storage. As we’ll see below, most authentication mechanisms within Spring Security return an instance of UserDetails as the principal.

The UserDetailsService
Another item to note from the above code fragment is that you can obtain a principal from the Authentication object. The principal is just an Object. Most of the time this can be cast into a UserDetails object. UserDetails is a core interface in Spring Security. It represents a principal, but in an extensible and application-specific way. Think of UserDetails as the adapter between your own user database and what Spring Security needs inside the SecurityContextHolder. Being a representation of something from your own user database, quite often you will cast the UserDetails to the original object that your application provided, so you can call business-specific methods (like getEmail(), getEmployeeNumber() and so on).

By now you’re probably wondering, so when do I provide a UserDetails object? How do I do that? I thought you said this thing was declarative and I didn’t need to write any Java code - what gives? The short answer is that there is a special interface called UserDetailsService. The only method on this interface accepts a String-based username argument and returns a UserDetails:

UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
This is the most common approach to loading information for a user within Spring Security and you will see it used throughout the framework whenever information on a user is required.

On successful authentication, UserDetails is used to build the Authentication object that is stored in the SecurityContextHolder (more on this below). The good news is that we provide a number of UserDetailsService implementations, including one that uses an in-memory map (InMemoryDaoImpl) and another that uses JDBC (JdbcDaoImpl). Most users tend to write their own, though, with their implementations often simply sitting on top of an existing Data Access Object (DAO) that represents their employees, customers, or other users of the application. Remember the advantage that whatever your UserDetailsService returns can always be obtained from the SecurityContextHolder using the above code fragment.

[Note]
There is often some confusion about UserDetailsService. It is purely a DAO for user data and performs no other function other than to supply that data to other components within the framework. In particular, it does not authenticate the user, which is done by the AuthenticationManager. In many cases it makes more sense to implement AuthenticationProvider directly if you require a custom authentication process.

GrantedAuthority
Besides the principal, another important method provided by Authentication is getAuthorities(). This method provides an array of GrantedAuthority objects. A GrantedAuthority is, not surprisingly, an authority that is granted to the principal. Such authorities are usually "roles", such as ROLE_ADMINISTRATOR or ROLE_HR_SUPERVISOR. These roles are later on configured for web authorization, method authorization and domain object authorization. Other parts of Spring Security are capable of interpreting these authorities, and expect them to be present. GrantedAuthority objects are usually loaded by the UserDetailsService.

Usually the GrantedAuthority objects are application-wide permissions. They are not specific to a given domain object. Thus, you wouldn’t likely have a GrantedAuthority to represent a permission to Employee object number 54, because if there are thousands of such authorities you would quickly run out of memory (or, at the very least, cause the application to take a long time to authenticate a user). Of course, Spring Security is expressly designed to handle this common requirement, but you’d instead use the project’s domain object security capabilities for this purpose.

Summary
Just to recap, the major building blocks of Spring Security that we’ve seen so far are:

SecurityContextHolder, to provide access to the SecurityContext.
SecurityContext, to hold the Authentication and possibly request-specific security information.
Authentication, to represent the principal in a Spring Security-specific manner.
GrantedAuthority, to reflect the application-wide permissions granted to a principal.
UserDetails, to provide the necessary information to build an Authentication object from your application’s DAOs or other source of security data.
UserDetailsService, to create a UserDetails when passed in a String-based username (or certificate ID or the like).
Now that you’ve gained an understanding of these repeatedly-used components, let’s take a closer look at the process of authentication.

8.1.3 Authentication
Spring Security can participate in many different authentication environments. While we recommend people use Spring Security for authentication and not integrate with existing Container Managed Authentication, it is nevertheless supported - as is integrating with your own proprietary authentication system.

What is authentication in Spring Security?
Let’s consider a standard authentication scenario that everyone is familiar with.

A user is prompted to log in with a username and password.
The system (successfully) verifies that the password is correct for the username.
The context information for that user is obtained (their list of roles and so on).
A security context is established for the user
The user proceeds, potentially to perform some operation which is potentially protected by an access control mechanism which checks the required permissions for the operation against the current security context information.
The first three items constitute the authentication process so we’ll take a look at how these take place within Spring Security.

The username and password are obtained and combined into an instance of UsernamePasswordAuthenticationToken (an instance of the Authentication interface, which we saw earlier).
The token is passed to an instance of AuthenticationManager for validation.
The AuthenticationManager returns a fully populated Authentication instance on successful authentication.
The security context is established by calling SecurityContextHolder.getContext().setAuthentication(…​), passing in the returned authentication object.
From that point on, the user is considered to be authenticated. Let’s look at some code as an example.

```
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuthenticationExample {
private static AuthenticationManager am = new SampleAuthenticationManager();

public static void main(String[] args) throws Exception {
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

    while(true) {
    System.out.println("Please enter your username:");
    String name = in.readLine();
    System.out.println("Please enter your password:");
    String password = in.readLine();
    try {
        Authentication request = new UsernamePasswordAuthenticationToken(name, password);
        Authentication result = am.authenticate(request);
        SecurityContextHolder.getContext().setAuthentication(result);
        break;
    } catch(AuthenticationException e) {
        System.out.println("Authentication failed: " + e.getMessage());
    }
    }
    System.out.println("Successfully authenticated. Security context contains: " +
            SecurityContextHolder.getContext().getAuthentication());
}
}

class SampleAuthenticationManager implements AuthenticationManager {
static final List<GrantedAuthority> AUTHORITIES = new ArrayList<GrantedAuthority>();

static {
    AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_USER"));
}

public Authentication authenticate(Authentication auth) throws AuthenticationException {
    if (auth.getName().equals(auth.getCredentials())) {
    return new UsernamePasswordAuthenticationToken(auth.getName(),
        auth.getCredentials(), AUTHORITIES);
    }
    throw new BadCredentialsException("Bad Credentials");
}
}
```


Here we have written a little program that asks the user to enter a username and password and performs the above sequence. The AuthenticationManager which we’ve implemented here will authenticate any user whose username and password are the same. It assigns a single role to every user. The output from the above will be something like:

```
Please enter your username:
bob
Please enter your password:
password
Authentication failed: Bad Credentials
Please enter your username:
bob
Please enter your password:
bob
Successfully authenticated. Security context contains: \
org.springframework.security.authentication.UsernamePasswordAuthenticationToken@441d0230: \
Principal: bob; Password: [PROTECTED]; \
Authenticated: true; Details: null; \
Granted Authorities: ROLE_USER
```

Note that you don’t normally need to write any code like this. The process will normally occur internally, in a web authentication filter for example. We’ve just included the code here to show that the question of what actually constitutes authentication in Spring Security has quite a simple answer. A user is authenticated when the SecurityContextHolder contains a fully populated Authentication object.

Setting the SecurityContextHolder Contents Directly
In fact, Spring Security doesn’t mind how you put the Authentication object inside the SecurityContextHolder. The only critical requirement is that the SecurityContextHolder contains an Authentication which represents a principal before the AbstractSecurityInterceptor (which we’ll see more about later) needs to authorize a user operation.

You can (and many users do) write their own filters or MVC controllers to provide interoperability with authentication systems that are not based on Spring Security. For example, you might be using Container-Managed Authentication which makes the current user available from a ThreadLocal or JNDI location. Or you might work for a company that has a legacy proprietary authentication system, which is a corporate "standard" over which you have little control. In situations like this it’s quite easy to get Spring Security to work, and still provide authorization capabilities. All you need to do is write a filter (or equivalent) that reads the third-party user information from a location, build a Spring Security-specific Authentication object, and put it into the SecurityContextHolder. In this case you also need to think about things which are normally taken care of automatically by the built-in authentication infrastructure. For example, you might need to pre-emptively create an HTTP session to cache the context between requests, before you write the response to the client footnote:[It isn’t possible to create a session once the response has been committed.

If you’re wondering how the AuthenticationManager is implemented in a real world example, we’ll look at that in the core services chapter.

8.1.4 Authentication in a Web Application
Now let’s explore the situation where you are using Spring Security in a web application (without web.xml security enabled). How is a user authenticated and the security context established?

Consider a typical web application’s authentication process:

You visit the home page, and click on a link.
A request goes to the server, and the server decides that you’ve asked for a protected resource.
As you’re not presently authenticated, the server sends back a response indicating that you must authenticate. The response will either be an HTTP response code, or a redirect to a particular web page.
Depending on the authentication mechanism, your browser will either redirect to the specific web page so that you can fill out the form, or the browser will somehow retrieve your identity (via a BASIC authentication dialogue box, a cookie, a X.509 certificate etc.).
The browser will send back a response to the server. This will either be an HTTP POST containing the contents of the form that you filled out, or an HTTP header containing your authentication details.
Next the server will decide whether or not the presented credentials are valid. If they’re valid, the next step will happen. If they’re invalid, usually your browser will be asked to try again (so you return to step two above).
The original request that you made to cause the authentication process will be retried. Hopefully you’ve authenticated with sufficient granted authorities to access the protected resource. If you have sufficient access, the request will be successful. Otherwise, you’ll receive back an HTTP error code 403, which means "forbidden".
Spring Security has distinct classes responsible for most of the steps described above. The main participants (in the order that they are used) are the ExceptionTranslationFilter, an AuthenticationEntryPoint and an "authentication mechanism", which is responsible for calling the AuthenticationManager which we saw in the previous section.

ExceptionTranslationFilter
ExceptionTranslationFilter is a Spring Security filter that has responsibility for detecting any Spring Security exceptions that are thrown. Such exceptions will generally be thrown by an AbstractSecurityInterceptor, which is the main provider of authorization services. We will discuss AbstractSecurityInterceptor in the next section, but for now we just need to know that it produces Java exceptions and knows nothing about HTTP or how to go about authenticating a principal. Instead the ExceptionTranslationFilter offers this service, with specific responsibility for either returning error code 403 (if the principal has been authenticated and therefore simply lacks sufficient access - as per step seven above), or launching an AuthenticationEntryPoint (if the principal has not been authenticated and therefore we need to go commence step three).

AuthenticationEntryPoint
The AuthenticationEntryPoint is responsible for step three in the above list. As you can imagine, each web application will have a default authentication strategy (well, this can be configured like nearly everything else in Spring Security, but let’s keep it simple for now). Each major authentication system will have its own AuthenticationEntryPoint implementation, which typically performs one of the actions described in step 3.

Authentication Mechanism
Once your browser submits your authentication credentials (either as an HTTP form post or HTTP header) there needs to be something on the server that "collects" these authentication details. By now we’re at step six in the above list. In Spring Security we have a special name for the function of collecting authentication details from a user agent (usually a web browser), referring to it as the "authentication mechanism". Examples are form-base login and Basic authentication. Once the authentication details have been collected from the user agent, an Authentication "request" object is built and then presented to the AuthenticationManager.

After the authentication mechanism receives back the fully-populated Authentication object, it will deem the request valid, put the Authentication into the SecurityContextHolder, and cause the original request to be retried (step seven above). If, on the other hand, the AuthenticationManager rejected the request, the authentication mechanism will ask the user agent to retry (step two above).

Storing the SecurityContext between requests
Depending on the type of application, there may need to be a strategy in place to store the security context between user operations. In a typical web application, a user logs in once and is subsequently identified by their session Id. The server caches the principal information for the duration session. In Spring Security, the responsibility for storing the SecurityContext between requests falls to the SecurityContextPersistenceFilter, which by default stores the context as an HttpSession attribute between HTTP requests. It restores the context to the SecurityContextHolder for each request and, crucially, clears the SecurityContextHolder when the request completes. You shouldn’t interact directly with the HttpSession for security purposes. There is simply no justification for doing so - always use the SecurityContextHolder instead.

Many other types of application (for example, a stateless RESTful web service) do not use HTTP sessions and will re-authenticate on every request. However, it is still important that the SecurityContextPersistenceFilter is included in the chain to make sure that the SecurityContextHolder is cleared after each request.

[Note]
In an application which receives concurrent requests in a single session, the same SecurityContext instance will be shared between threads. Even though a ThreadLocal is being used, it is the same instance that is retrieved from the HttpSession for each thread. This has implications if you wish to temporarily change the context under which a thread is running. If you just use SecurityContextHolder.getContext(), and call setAuthentication(anAuthentication) on the returned context object, then the Authentication object will change in all concurrent threads which share the same SecurityContext instance. You can customize the behaviour of SecurityContextPersistenceFilter to create a completely new SecurityContext for each request, preventing changes in one thread from affecting another. Alternatively you can create a new instance just at the point where you temporarily change the context. The method SecurityContextHolder.createEmptyContext() always returns a new context instance.

8.1.5 Access-Control (Authorization) in Spring Security

The main interface responsible for making access-control decisions in Spring Security is the AccessDecisionManager. It has a decide method which takes an Authentication object representing the principal requesting access, a "secure object" (see below) and a list of security metadata attributes which apply for the object (such as a list of roles which are required for access to be granted).

Security and AOP Advice
If you’re familiar with AOP, you’d be aware there are different types of advice available: before, after, throws and around. An around advice is very useful, because an advisor can elect whether or not to proceed with a method invocation, whether or not to modify the response, and whether or not to throw an exception. Spring Security provides an around advice for method invocations as well as web requests. We achieve an around advice for method invocations using Spring’s standard AOP support and we achieve an around advice for web requests using a standard Filter.

For those not familiar with AOP, the key point to understand is that Spring Security can help you protect method invocations as well as web requests. Most people are interested in securing method invocations on their services layer. This is because the services layer is where most business logic resides in current-generation Java EE applications. If you just need to secure method invocations in the services layer, Spring’s standard AOP will be adequate. If you need to secure domain objects directly, you will likely find that AspectJ is worth considering.

You can elect to perform method authorization using AspectJ or Spring AOP, or you can elect to perform web request authorization using filters. You can use zero, one, two or three of these approaches together. The mainstream usage pattern is to perform some web request authorization, coupled with some Spring AOP method invocation authorization on the services layer.

Secure Objects and the AbstractSecurityInterceptor
So what is a "secure object" anyway? Spring Security uses the term to refer to any object that can have security (such as an authorization decision) applied to it. The most common examples are method invocations and web requests.

Each supported secure object type has its own interceptor class, which is a subclass of AbstractSecurityInterceptor. Importantly, by the time the AbstractSecurityInterceptor is called, the SecurityContextHolder will contain a valid Authentication if the principal has been authenticated.

AbstractSecurityInterceptor provides a consistent workflow for handling secure object requests, typically:

Look up the "configuration attributes" associated with the present request
Submitting the secure object, current Authentication and configuration attributes to the AccessDecisionManager for an authorization decision
Optionally change the Authentication under which the invocation takes place
Allow the secure object invocation to proceed (assuming access was granted)
Call the AfterInvocationManager if configured, once the invocation has returned. If the invocation raised an exception, the AfterInvocationManager will not be invoked.
What are Configuration Attributes?
A "configuration attribute" can be thought of as a String that has special meaning to the classes used by AbstractSecurityInterceptor. They are represented by the interface ConfigAttribute within the framework. They may be simple role names or have more complex meaning, depending on the how sophisticated the AccessDecisionManager implementation is. The AbstractSecurityInterceptor is configured with a SecurityMetadataSource which it uses to look up the attributes for a secure object. Usually this configuration will be hidden from the user. Configuration attributes will be entered as annotations on secured methods or as access attributes on secured URLs. For example, when we saw something like <intercept-url pattern='/secure/**' access='ROLE_A,ROLE_B'/> in the namespace introduction, this is saying that the configuration attributes ROLE_A and ROLE_B apply to web requests matching the given pattern. In practice, with the default AccessDecisionManager configuration, this means that anyone who has a GrantedAuthority matching either of these two attributes will be allowed access. Strictly speaking though, they are just attributes and the interpretation is dependent on the AccessDecisionManager implementation. The use of the prefix ROLE_ is a marker to indicate that these attributes are roles and should be consumed by Spring Security’s RoleVoter. This is only relevant when a voter-based AccessDecisionManager is in use. We’ll see how the AccessDecisionManager is implemented in the authorization chapter.

RunAsManager
Assuming AccessDecisionManager decides to allow the request, the AbstractSecurityInterceptor will normally just proceed with the request. Having said that, on rare occasions users may want to replace the Authentication inside the SecurityContext with a different Authentication, which is handled by the AccessDecisionManager calling a RunAsManager. This might be useful in reasonably unusual situations, such as if a services layer method needs to call a remote system and present a different identity. Because Spring Security automatically propagates security identity from one server to another (assuming you’re using a properly-configured RMI or HttpInvoker remoting protocol client), this may be useful.

AfterInvocationManager
Following the secure object invocation proceeding and then returning - which may mean a method invocation completing or a filter chain proceeding - the AbstractSecurityInterceptor gets one final chance to handle the invocation. At this stage the AbstractSecurityInterceptor is interested in possibly modifying the return object. We might want this to happen because an authorization decision couldn’t be made "on the way in" to a secure object invocation. Being highly pluggable, AbstractSecurityInterceptor will pass control to an AfterInvocationManager to actually modify the object if needed. This class can even entirely replace the object, or throw an exception, or not change it in any way as it chooses. The after-invocation checks will only be executed if the invocation is successful. If an exception occurs, the additional checks will be skipped.

AbstractSecurityInterceptor and its related objects are shown in Figure 8.1, “Security interceptors and the "secure object" model”

Figure 8.1. Security interceptors and the "secure object" model

Abstract Security Interceptor

Extending the Secure Object Model
Only developers contemplating an entirely new way of intercepting and authorizing requests would need to use secure objects directly. For example, it would be possible to build a new secure object to secure calls to a messaging system. Anything that requires security and also provides a way of intercepting a call (like the AOP around advice semantics) is capable of being made into a secure object. Having said that, most Spring applications will simply use the three currently supported secure object types (AOP Alliance MethodInvocation, AspectJ JoinPoint and web request FilterInvocation) with complete transparency.

8.1.6 Localization
Spring Security supports localization of exception messages that end users are likely to see. If your application is designed for English-speaking users, you don’t need to do anything as by default all Security messages are in English. If you need to support other locales, everything you need to know is contained in this section.

All exception messages can be localized, including messages related to authentication failures and access being denied (authorization failures). Exceptions and logging messages that are focused on developers or system deployers (including incorrect attributes, interface contract violations, using incorrect constructors, startup time validation, debug-level logging) are not localized and instead are hard-coded in English within Spring Security’s code.

Shipping in the spring-security-core-xx.jar you will find an org.springframework.security package that in turn contains a messages.properties file, as well as localized versions for some common languages. This should be referred to by your ApplicationContext, as Spring Security classes implement Spring’s MessageSourceAware interface and expect the message resolver to be dependency injected at application context startup time. Usually all you need to do is register a bean inside your application context to refer to the messages. An example is shown below:

```
<bean id="messageSource"
    class="org.springframework.context.support.ReloadableResourceBundleMessageSource">
<property name="basename" value="classpath:org/springframework/security/messages"/>
</bean>
```

The messages.properties is named in accordance with standard resource bundles and represents the default language supported by Spring Security messages. This default file is in English.

If you wish to customize the messages.properties file, or support other languages, you should copy the file, rename it accordingly, and register it inside the above bean definition. There are not a large number of message keys inside this file, so localization should not be considered a major initiative. If you do perform localization of this file, please consider sharing your work with the community by logging a JIRA task and attaching your appropriately-named localized version of messages.properties.

Spring Security relies on Spring’s localization support in order to actually lookup the appropriate message. In order for this to work, you have to make sure that the locale from the incoming request is stored in Spring’s org.springframework.context.i18n.LocaleContextHolder. Spring MVC’s DispatcherServlet does this for your application automatically, but since Spring Security’s filters are invoked before this, the LocaleContextHolder needs to be set up to contain the correct Locale before the filters are called. You can either do this in a filter yourself (which must come before the Spring Security filters in web.xml) or you can use Spring’s RequestContextFilter. Please refer to the Spring Framework documentation for further details on using localization with Spring.

The "contacts" sample application is set up to use localized messages.

8.2 Core Services
Now that we have a high-level overview of the Spring Security architecture and its core classes, let’s take a closer look at one or two of the core interfaces and their implementations, in particular the AuthenticationManager, UserDetailsService and the AccessDecisionManager. These crop up regularly throughout the remainder of this document so it’s important you know how they are configured and how they operate.

8.2.1 The AuthenticationManager, ProviderManager and AuthenticationProvider
The AuthenticationManager is just an interface, so the implementation can be anything we choose, but how does it work in practice? What if we need to check multiple authentication databases or a combination of different authentication services such as a database and an LDAP server?

The default implementation in Spring Security is called ProviderManager and rather than handling the authentication request itself, it delegates to a list of configured AuthenticationProvider s, each of which is queried in turn to see if it can perform the authentication. Each provider will either throw an exception or return a fully populated Authentication object. Remember our good friends, UserDetails and UserDetailsService? If not, head back to the previous chapter and refresh your memory. The most common approach to verifying an authentication request is to load the corresponding UserDetails and check the loaded password against the one that has been entered by the user. This is the approach used by the DaoAuthenticationProvider (see below). The loaded UserDetails object - and particularly the GrantedAuthority s it contains - will be used when building the fully populated Authentication object which is returned from a successful authentication and stored in the SecurityContext.

If you are using the namespace, an instance of ProviderManager is created and maintained internally, and you add providers to it by using the namespace authentication provider elements (see the namespace chapter). In this case, you should not declare a ProviderManager bean in your application context. However, if you are not using the namespace then you would declare it like so:

```
<bean id="authenticationManager"
        class="org.springframework.security.authentication.ProviderManager">
    <constructor-arg>
        <list>
            <ref local="daoAuthenticationProvider"/>
            <ref local="anonymousAuthenticationProvider"/>
            <ref local="ldapAuthenticationProvider"/>
        </list>
    </constructor-arg>
</bean>
```

In the above example we have three providers. They are tried in the order shown (which is implied by the use of a List), with each provider able to attempt authentication, or skip authentication by simply returning null. If all implementations return null, the ProviderManager will throw a ProviderNotFoundException. If you’re interested in learning more about chaining providers, please refer to the ProviderManager Javadoc.

Authentication mechanisms such as a web form-login processing filter are injected with a reference to the ProviderManager and will call it to handle their authentication requests. The providers you require will sometimes be interchangeable with the authentication mechanisms, while at other times they will depend on a specific authentication mechanism. For example, DaoAuthenticationProvider and LdapAuthenticationProvider are compatible with any mechanism which submits a simple username/password authentication request and so will work with form-based logins or HTTP Basic authentication. On the other hand, some authentication mechanisms create an authentication request object which can only be interpreted by a single type of AuthenticationProvider. An example of this would be JA-SIG CAS, which uses the notion of a service ticket and so can therefore only be authenticated by a CasAuthenticationProvider. You needn’t be too concerned about this, because if you forget to register a suitable provider, you’ll simply receive a ProviderNotFoundException when an attempt to authenticate is made.

Erasing Credentials on Successful Authentication
By default (from Spring Security 3.1 onwards) the ProviderManager will attempt to clear any sensitive credentials information from the Authentication object which is returned by a successful authentication request. This prevents information like passwords being retained longer than necessary.

This may cause issues when you are using a cache of user objects, for example, to improve performance in a stateless application. If the Authentication contains a reference to an object in the cache (such as a UserDetails instance) and this has its credentials removed, then it will no longer be possible to authenticate against the cached value. You need to take this into account if you are using a cache. An obvious solution is to make a copy of the object first, either in the cache implementation or in the AuthenticationProvider which creates the returned Authentication object. Alternatively, you can disable the eraseCredentialsAfterAuthentication property on ProviderManager. See the Javadoc for more information.

DaoAuthenticationProvider
The simplest AuthenticationProvider implemented by Spring Security is DaoAuthenticationProvider, which is also one of the earliest supported by the framework. It leverages a UserDetailsService (as a DAO) in order to lookup the username, password and GrantedAuthority s. It authenticates the user simply by comparing the password submitted in a UsernamePasswordAuthenticationToken against the one loaded by the UserDetailsService. Configuring the provider is quite simple:

```
<bean id="daoAuthenticationProvider"
    class="org.springframework.security.authentication.dao.DaoAuthenticationProvider">
<property name="userDetailsService" ref="inMemoryDaoImpl"/>
<property name="passwordEncoder" ref="passwordEncoder"/>
</bean>
```

The PasswordEncoder is optional. A PasswordEncoder provides encoding and decoding of passwords presented in the UserDetails object that is returned from the configured UserDetailsService. This will be discussed in more detail below.

8.2.2 UserDetailsService Implementations
As mentioned in the earlier in this reference guide, most authentication providers take advantage of the UserDetails and UserDetailsService interfaces. Recall that the contract for UserDetailsService is a single method:

UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
The returned UserDetails is an interface that provides getters that guarantee non-null provision of authentication information such as the username, password, granted authorities and whether the user account is enabled or disabled. Most authentication providers will use a UserDetailsService, even if the username and password are not actually used as part of the authentication decision. They may use the returned UserDetails object just for its GrantedAuthority information, because some other system (like LDAP or X.509 or CAS etc) has undertaken the responsibility of actually validating the credentials.

Given UserDetailsService is so simple to implement, it should be easy for users to retrieve authentication information using a persistence strategy of their choice. Having said that, Spring Security does include a couple of useful base implementations, which we’ll look at below.

In-Memory Authentication
Is easy to use create a custom UserDetailsService implementation that extracts information from a persistence engine of choice, but many applications do not require such complexity. This is particularly true if you’re building a prototype application or just starting integrating Spring Security, when you don’t really want to spend time configuring databases or writing UserDetailsService implementations. For this sort of situation, a simple option is to use the user-service element from the security namespace:

```
<user-service id="userDetailsService">
<!-- Password is prefixed with {noop} to indicate to DelegatingPasswordEncoder that
NoOpPasswordEncoder should be used. This is not safe for production, but makes reading
in samples easier. Normally passwords should be hashed using BCrypt -->
<user name="jimi" password="{noop}jimispassword" authorities="ROLE_USER, ROLE_ADMIN" />
<user name="bob" password="{noop}bobspassword" authorities="ROLE_USER" />
</user-service>
This also supports the use of an external properties file:

<user-service id="userDetailsService" properties="users.properties"/>
```

The properties file should contain entries in the form

username=password,grantedAuthority[,grantedAuthority][,enabled|disabled]
For example

jimi=jimispassword,ROLE_USER,ROLE_ADMIN,enabled
bob=bobspassword,ROLE_USER,enabled
JdbcDaoImpl
Spring Security also includes a UserDetailsService that can obtain authentication information from a JDBC data source. Internally Spring JDBC is used, so it avoids the complexity of a fully-featured object relational mapper (ORM) just to store user details. If your application does use an ORM tool, you might prefer to write a custom UserDetailsService to reuse the mapping files you’ve probably already created. Returning to JdbcDaoImpl, an example configuration is shown below:

```
<bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
<property name="driverClassName" value="org.hsqldb.jdbcDriver"/>
<property name="url" value="jdbc:hsqldb:hsql://localhost:9001"/>
<property name="username" value="sa"/>
<property name="password" value=""/>
</bean>

<bean id="userDetailsService"
    class="org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl">
<property name="dataSource" ref="dataSource"/>
</bean>
```

You can use different relational database management systems by modifying the DriverManagerDataSource shown above. You can also use a global data source obtained from JNDI, as with any other Spring configuration.

Authority Groups
By default, JdbcDaoImpl loads the authorities for a single user with the assumption that the authorities are mapped directly to users (see the database schema appendix). An alternative approach is to partition the authorities into groups and assign groups to the user. Some people prefer this approach as a means of administering user rights. See the JdbcDaoImpl Javadoc for more information on how to enable the use of group authorities. The group schema is also included in the appendix.

8.2.3 Password Encoding
Spring Security’s PasswordEncoder interface is used to perform a one way transformation of a password to allow the password to be stored securely. Given PasswordEncoder is a one way transformation, it is not intended when the password transformation needs to be two way (i.e. storing credentials used to authenticate to a database). Typically PasswordEncoder is used for storing a password that needs to be compared to a user provided password at the time of authentication.

Password History
Throughout the years the standard mechanism for storing passwords has evolved. In the beginning passwords were stored in plain text. The passwords were assumed to be safe because the data store the passwords were saved in required credentials to access it. However, malicious users were able to find ways to get large "data dumps" of usernames and passwords using attacks like SQL Injection. As more and more user credentials became public security experts realized we needed to do more to protect users passwords.

Developers were then encouraged to store passwords after running them through a one way hash such as SHA-256. When a user tried to authenticate, the hashed password would be compared to the hash of the password that they typed. This meant that the system only needed to store the one way hash of the password. If a breach occurred, then only the one way hashes of the passwords were exposed. Since the hashes were one way and it was computationally difficult to guess the passwords given the hash, it would not be worth the effort to figure out each password in the system. To defeat this new system malicious users decided to create lookup tables known as Rainbow Tables. Rather than doing the work of guessing each password every time, they computed the password once and stored it in a lookup table.

To mitigate the effectiveness of Rainbow Tables, developers were encouraged to use salted passwords. Instead of using just the password as input to the hash function, random bytes (known as salt) would be generated for every users' password. The salt and the user’s password would be ran through the hash function which produced a unique hash. The salt would be stored alongside the user’s password in clear text. Then when a user tried to authenticate, the hashed password would be compared to the hash of the stored salt and the password that they typed. The unique salt meant that Rainbow Tables were no longer effective because the hash was different for every salt and password combination.

In modern times we realize that cryptographic hashes (like SHA-256) are no longer secure. The reason is that with modern hardware we can perform billions of hash calculations a second. This means that we can crack each password individually with ease.

Developers are now encouraged to leverage adaptive one-way functions to store a password. Validation of passwords with adaptive one-way functions are intentionally resource (i.e. CPU, memory, etc) intensive. An adaptive one-way function allows configuring a "work factor" which can grow as hardware gets better. It is recommended that the "work factor" be tuned to take about 1 second to verify a password on your system. This trade off is to make it difficult for attackers to crack the password, but not so costly it puts excessive burden on your own system. Spring Security has attempted to provide a good starting point for the "work factor", but users are encouraged to customize the "work factor" for their own system since the performance will vary drastically from system to system. Examples of adaptive one-way functions that should be used include bcrypt, PBKDF2, scrypt, and Argon2.

Because adaptive one-way functions are intentionally resource intensive, validating a username and password for every request will degrade performance of an application significantly. There is nothing Spring Security (or any other library) can do to speed up the validation of the password since security is gained by making the validation resource intensive. Users are encouraged to exchange the long term credentials (i.e. username and password) for a short term credential (i.e. session, OAuth Token, etc). The short term credential can be validated quickly without any loss in security.

DelegatingPasswordEncoder
Prior to Spring Security 5.0 the default PasswordEncoder was NoOpPasswordEncoder which required plain text passwords. Based upon the Password History section you might expect that the default PasswordEncoder is now something like BCryptPasswordEncoder. However, this ignores three real world problems:

There are many applications using old password encodings that cannot easily migrate
The best practice for password storage will change again.
As a framework Spring Security cannot make breaking changes frequently
Instead Spring Security introduces DelegatingPasswordEncoder which solves all of the problems by:

Ensuring that passwords are encoded using the current password storage recommendations
Allowing for validating passwords in modern and legacy formats
Allowing for upgrading the encoding in the future
You can easily construct an instance of DelegatingPasswordEncoder using PasswordEncoderFactories.

PasswordEncoder passwordEncoder =
    PasswordEncoderFactories.createDelegatingPasswordEncoder();
Alternatively, you may create your own custom instance. For example:

```
String idForEncode = "bcrypt";
Map encoders = new HashMap<>();
encoders.put(idForEncode, new BCryptPasswordEncoder());
encoders.put("noop", NoOpPasswordEncoder.getInstance());
encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
encoders.put("scrypt", new SCryptPasswordEncoder());
encoders.put("sha256", new StandardPasswordEncoder());

PasswordEncoder passwordEncoder =
    new DelegatingPasswordEncoder(idForEncode, encoders);
```

Password Storage Format
The general format for a password is:

{id}encodedPassword
Such that id is an identifier used to look up which PasswordEncoder should be used and encodedPassword is the original encoded password for the selected PasswordEncoder. The id must be at the beginning of the password, start with { and end with }. If the id cannot be found, the id will be null. For example, the following might be a list of passwords encoded using different id. All of the original passwords are "password".

```
{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG 1
{noop}password 2
{pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc 3
{scrypt}$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=  4
{sha256}97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0 5

```

1

The first password would have a PasswordEncoder id of bcrypt and encodedPassword of `$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG`. When matching it would delegate to BCryptPasswordEncoder

2

The second password would have a PasswordEncoder id of noop and encodedPassword of password. When matching it would delegate to NoOpPasswordEncoder

3

The third password would have a PasswordEncoder id of pbkdf2 and encodedPassword of 5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc. When matching it would delegate to Pbkdf2PasswordEncoder

4

The fourth password would have a PasswordEncoder id of scrypt and encodedPassword of `$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=` When matching it would delegate to SCryptPasswordEncoder

5

The final password would have a PasswordEncoder id of sha256 and encodedPassword of `97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0`. When matching it would delegate to StandardPasswordEncoder

[Note]
Some users might be concerned that the storage format is provided for a potential hacker. This is not a concern because the storage of the password does not rely on the algorithm being a secret. Additionally, most formats are easy for an attacker to figure out without the prefix. For example, BCrypt passwords often start with $2a$.

Password Encoding
The idForEncode passed into the constructor determines which PasswordEncoder will be used for encoding passwords. In the DelegatingPasswordEncoder we constructed above, that means that the result of encoding password would be delegated to BCryptPasswordEncoder and be prefixed with {bcrypt}. The end result would look like:

`{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG`
Password Matching
Matching is done based upon the {id} and the mapping of the id to the PasswordEncoder provided in the constructor. Our example in the section called “Password Storage Format” provides a working example of how this is done. By default, the result of invoking matches(CharSequence, String) with a password and an id that is not mapped (including a null id) will result in an IllegalArgumentException. This behavior can be customized using DelegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(PasswordEncoder).

By using the id we can match on any password encoding, but encode passwords using the most modern password encoding. This is important, because unlike encryption, password hashes are designed so that there is no simple way to recover the plaintext. Since there is no way to recover the plaintext, it makes it difficult to migrate the passwords. While it is simple for users to migrate NoOpPasswordEncoder, we chose to include it by default to make it simple for the getting started experience.

Getting Started Experience
If you are putting together a demo or a sample, it is a bit cumbersome to take time to hash the passwords of your users. There are convenience mechanisms to make this easier, but this is still not intended for production.

```
User user = User.withDefaultPasswordEncoder()
  .username("user")
  .password("password")
  .roles("user")
  .build();
System.out.println(user.getPassword());
// {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
```

If you are creating multiple users, you can also reuse the builder.

```
UserBuilder users = User.withDefaultPasswordEncoder();
User user = users
  .username("user")
  .password("password")
  .roles("USER")
  .build();
User admin = users
  .username("admin")
  .password("password")
  .roles("USER","ADMIN")
  .build();
```

This does hash the password that is stored, but the passwords are still exposed in memory and in the compiled source code. Therefore, it is still not considered secure for a production environment. For production, you should hash your passwords externally.

Troubleshooting
The following error occurs when one of the passwords that are stored has no id as described in the section called “Password Storage Format”.

```
java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
    at org.springframework.security.crypto.password.DelegatingPasswordEncoder$UnmappedIdPasswordEncoder.matches(DelegatingPasswordEncoder.java:233)
    at org.springframework.security.crypto.password.DelegatingPasswordEncoder.matches(DelegatingPasswordEncoder.java:196)
```

The easiest way to resolve the error is to switch to explicitly provide the PasswordEncoder that you passwords are encoded with. The easiest way to resolve it is to figure out how your passwords are currently being stored and explicitly provide the correct PasswordEncoder. If you are migrating from Spring Security 4.2.x you can revert to the previous behavior by exposing a NoOpPasswordEncoder bean. For example, if you are using Java Configuration, you can create a configuration that looks like:

[Warning]
Reverting to NoOpPasswordEncoder is not considered to be secure. You should instead migrate to using DelegatingPasswordEncoder to support secure password encoding.
```
@Bean
public static NoOpPasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
}
```

if you are using XML configuration, you can expose a PasswordEncoder with the id passwordEncoder:

```
<b:bean id="passwordEncoder"
        class="org.springframework.security.crypto.password.NoOpPasswordEncoder" factory-method="getInstance"/>
```

Alternatively, you can prefix all of your passwords with the correct id and continue to use DelegatingPasswordEncoder. For example, if you are using BCrypt, you would migrate your password from something like:

`$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG`
to

`{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG`
For a complete listing of the mappings refer to the Javadoc on PasswordEncoderFactories.

BCryptPasswordEncoder
The BCryptPasswordEncoder implementation uses the widely supported bcrypt algorithm to hash the passwords. In order to make it more resistent to password cracking, bcrypt is deliberately slow. Like other adaptive one-way functions, it should be tuned to take about 1 second to verify a password on your system.

```
// Create an encoder with strength 16
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(16);
String result = encoder.encode("myPassword");
assertTrue(encoder.matches("myPassword", result));
```

Pbkdf2PasswordEncoder
The Pbkdf2PasswordEncoder implementation uses the PBKDF2 algorithm to hash the passwords. In order to defeat password cracking PBKDF2 is a deliberately slow algorithm. Like other adaptive one-way functions, it should be tuned to take about 1 second to verify a password on your system. This algorithm is a good choice when FIPS certification is required.


```
// Create an encoder with all the defaults
Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder();
String result = encoder.encode("myPassword");
assertTrue(encoder.matches("myPassword", result));
```

SCryptPasswordEncoder
The SCryptPasswordEncoder implementation uses scrypt algorithm to hash the passwords. In order to defeat password cracking on custom hardware scrypt is a deliberately slow algorithm that requires large amounts of memory. Like other adaptive one-way functions, it should be tuned to take about 1 second to verify a password on your system.

```
// Create an encoder with all the defaults
SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
String result = encoder.encode("myPassword");
assertTrue(encoder.matches("myPassword", result));
```

Other PasswordEncoders
There are a significant number of other PasswordEncoder implementations that exist entirely for backward compatibility. They are all deprecated to indicate that they are no longer considered secure. However, there are no plans to remove them since it is difficult to migrate existing legacy systems.

8.2.4 Jackson Support
Spring Security has added Jackson Support for persisting Spring Security related classes. This can improve the performance of serializing Spring Security related classes when working with distributed sessions (i.e. session replication, Spring Session, etc).

To use it, register the JacksonJacksonModules.getModules(ClassLoader) as Jackson Modules.

```
ObjectMapper mapper = new ObjectMapper();
ClassLoader loader = getClass().getClassLoader();
List<Module> modules = SecurityJackson2Modules.getModules(loader);
mapper.registerModules(modules);

// ... use ObjectMapper as normally ...
SecurityContext context = new SecurityContextImpl();
// ...
String json = mapper.writeValueAsString(context);
```
