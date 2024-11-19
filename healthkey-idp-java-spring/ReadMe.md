# healthkey-idp-example
This is a small project, written using Java and Spring.

# Things to read before
We've made use of Spring Authorisation Server, as it comes with everything we need out of pocket: <https://docs.spring.io/spring-authorization-server/reference/overview.html>

# Limitations
We'd like for you to use https, but if not possible, let us know and we can enable http for testing purposes.

# Steps to use this
1. This project is supposed to be used just a starting point (it's not production ready or anything close)
2. In application.yml, you would need to change the redirect_uri, to the one we send you
3. In the home.html template, you will need to change the URL of the button to the one we give you
4. You'll need to pluck your own user repository into the process, as currently it's using a dummy repo
5. You'll probably want to add your own consent page, if you don't want to use the default one

# What we'll need from you
We just need the client id and client secret. We'll get all the endpoints we need from /.well-known/openid-configuration (Srping should publish this one automatically).