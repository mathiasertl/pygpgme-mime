# -*- coding: utf-8 -*-
#
# This file is part of pygpgme-mime (https://github.com/mathiasertl/pygpgme-mime).
#
# pygpgme-mime is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# pygpgme-mime is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with pygpgme-mime. If
# not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals, absolute_import

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.core.mail import SafeMIMEMultipart
from django.utils.encoding import force_text
from six.moves.email_mime_multipart import MIMEMultipart

from . import rfc3156

class GPGEmailMessage(EmailMultiAlternatives):
    def message(self):
        encoding = self.encoding or settings.DEFAULT_CHARSET
        signers = self.gpg_signers
        recipients = self.gpg_recipients
        context = self.gpg_context

        if recipients or signers or (context and context.signers):
            orig_msg = super(GPGEmailMessage, self).message()

            if isinstance(orig_msg, MIMEMultipart):
                to_encrypt = MIMEMultipart(_subtype='alternative', _subparts=orig_msg.get_payload())
            else:  # No attachments were added
                to_encrypt = orig_msg.get_payload()

            msg = rfc3156(to_encrypt, recipients=recipients, signers=signers, context=context,
                          always_trust=self.gpg_always_trust)

            # if this is already a Multipart message, we can just set the payload and return it
            if isinstance(orig_msg, MIMEMultipart):
                orig_msg.set_payload(msg.get_payload())
                orig_msg.set_param('protocol', self.protocol)

                with open('/home/mati/git/mati/pygpgme-mime/test/final-multipart.eml', 'wb') as fp:
                    fp.write(orig_msg.as_bytes())

                return orig_msg

            body, sig = msg.get_payload()

            gpg_msg = SafeMIMEMultipart(_subtype=self.alternative_subtype, encoding=encoding)
            gpg_msg.attach(body)
            gpg_msg.attach(sig)
            gpg_msg.set_param('protocol', self.protocol)
            gpg_msg['Subject'] = self.subject
            gpg_msg['From'] = self.extra_headers.get('From', self.from_email)
            gpg_msg['To'] = self.extra_headers.get('To', ', '.join(map(force_text, self.to)))
            if self.cc:
                gpg_msg['Cc'] = ', '.join(map(force_text, self.cc))
            if self.reply_to:
                gpg_msg['Reply-To'] = self.extra_headers.get('Reply-To', ', '.join(map(force_text, self.reply_to)))

            with open('/home/mati/git/mati/pygpgme-mime/test/final-normal.eml', 'wb') as fp:
                fp.write(gpg_msg.as_bytes())

            # TODO: We don't yet know how to get the correct value
            gpg_msg.set_param('micalg', 'pgp-sha256')

            return gpg_msg
        else:
            return super(GPGEmailMessage, self).message()

    def __init__(self, *args, **kwargs):
        self.gpg_signers = kwargs.pop('gpg_signers', None)
        self.gpg_recipients = kwargs.pop('gpg_recipients', None)
        self.gpg_context = kwargs.pop('gpg_context', None)
        self.gpg_always_trust = kwargs.pop('gpg_always_trust', None)

        if self.gpg_recipients:
            self.protocol = 'application/pgp-encrypted'
            self.mixed_subtype = 'encrypted'
            self.alternative_subtype = 'encrypted'
        elif self.gpg_signers or (self.gpg_context and self.gpg_context.signers):
            self.protocol = 'application/pgp-signature'
            self.mixed_subtype = 'signed'
            self.alternative_subtype = 'signed'

        super(GPGEmailMessage, self).__init__(*args, **kwargs)
