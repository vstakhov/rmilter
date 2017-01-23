# About Rmilter

## Introduction

[Rmilter](https://rspamd.com/rmilter/) is used to integrate Rspamd with `milter` compatible MTA, for example [Postfix](http://postfix.org) or [Sendmail](http://sendmail.org).

This project is now not under active development, however, bug fixes and Rspamd integration features are still considered.

Historically, Rmilter supported many other features besides Rspamd integration. So far, all these features are implemented in Rspamd which allows to simplify integration with different MTA (e.g. Exim, Haraka or other non-milter compatible servers). Therefore, if you use this functionality you should consider switching it to Rspamd where all equal features are usually better implemented and have active and actual support.

The list of features includes the following ones:

- Greylisting - provided by [greylisting module](https://rspamd.com/doc/modules/greylisting.html)
- Ratelimit - is done by [ratelimit module](https://rspamd.com/doc/modules/ratelimit.html)
- Replies whitelisting - is implemented in [replies module](https://rspamd.com/doc/modules/replies.html)
- Antivirus filtering - provided now by [antivirus module](https://rspamd.com/doc/modules/antivirus.html)
- DCC checks - are now done in [dcc module](https://rspamd.com/doc/modules/dcc.html)
- Dkim signing - can be done now by using of [dkim module](https://rspamd.com/doc/modules/dkim.html#dkim-signatures) and also by a more simple [dkim signing module](https://rspamd.com/doc/modules/dkim_signing.html)

All duplicating features are still kept in Rmilter for compatibility reasons. However, no further development or bug fixes will likely be done for them.

Rmilter project page can be found on GitHub: <http://github.com/vstakhov/rmilter>.

## Rmilter configuration

Rmilter configuration format is described in the **[following page](https://rspamd.com/rmilter/configuration.html)**.

## Postfix settings

Here is a scheme that demonstrates Rspamd and Rmilter integration using Postfix MTA:

<img class="img-responsive" src="https://rspamd.com/img/rspamd-schemes.007.png">

There are several useful settings for postfix to work with this milter:

    smtpd_milters = unix:/var/run/rmilter/rmilter.sock
    milter_mail_macros =  i {mail_addr} {client_addr} {client_name} {auth_authen}
    milter_protocol = 6