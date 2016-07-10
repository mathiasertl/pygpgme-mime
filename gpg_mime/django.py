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
from six.moves.email_mime_multipart import MIMEMultipart

from . import rfc3156


class GPGEmailMessage(EmailMultiAlternatives):
    @property
    def signed(self):
        return bool(self.gpg_signers or (self.gpg_context and self.gpg_context.signers))

    @property
    def encrypted(self):
        return bool(self.gpg_recipients)

    def message(self):
        # If neither encryption nor signing was request, we just return the normal message
        orig_msg = super(GPGEmailMessage, self).message()
        if not self.encrypted and not self.signed:
            return orig_msg

        encoding = self.encoding or settings.DEFAULT_CHARSET
        signers = self.gpg_signers
        recipients = self.gpg_recipients
        context = self.gpg_context

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

            # Set the micalg Content-Type parameter. Only present in messages that are only signed
            # TODO:We don't yet know how to get the correct value, we just return GPGs default
            if self.encrypted is False:
                orig_msg.set_param('micalg', 'pgp-sha256')

            return orig_msg

        # This message was not a multipart message, so we create a new multipart message and attach
        # the payload of the signed and/or encrypted payload.
        body, sig = msg.get_payload()

        gpg_msg = SafeMIMEMultipart(_subtype=self.alternative_subtype, encoding=encoding)
        gpg_msg.attach(body)
        gpg_msg.attach(sig)

        for key, value in orig_msg.items():
            if key.lower() in ['Content-Type', 'Content-Transfer-Encoding']:
                continue
            gpg_msg[key] = value

        # TODO: We don't yet know how to get the correct value
        if self.encrypted is False:
            gpg_msg.set_param('micalg', 'pgp-sha256')
        gpg_msg.set_param('protocol', self.protocol)

        return gpg_msg

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
