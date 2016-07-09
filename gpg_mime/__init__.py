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

from email.mime.application import MIMEApplication

import gpgme
import six

from six.moves.email_mime_multipart import MIMEMultipart
from six.moves.email_mime_text import MIMEText
from six.moves.email_mime_base import MIMEBase
from email.encoders import encode_noop


def rfc3156(message, recipients=None, signers=None, context=None, always_trust=False):
    """
    Parameters
    ----------

    message : :py:class:`email.mime.base.MIMEBase` or str
    context : :py:class:`pygpgme.Context`, optional
        If not set, a new object with default parameters will be created.
    always_trust : bool, optional
        If ``True``, always trust recipient keys.
    """

    if (not signers and not recipients) or context and context.signers:
        raise ValueError("No signers or recipients given.")

    if isinstance(message, six.string_types):
        message = MIMEText(message)
        del message['MIME-Version']

    if recipients is None:
        recipients = []
    elif isinstance(recipients, six.string_types):
        recipients = [recipients]

    if signers is None:
        signers = []
    elif isinstance(signers, six.string_types):
        signers = [signers]

    if context is None:
        context = gpgme.Context()
    context.armor = True

    # signers/recpiients may either be a string or a key from the context
    signers = [(context.get_key(k) if isinstance(k, six.string_types) else k) for k in signers]
    recipients = [context.get_key(k) if isinstance(k, six.string_types) else k for k in recipients]

    if signers:
        context.signers = signers

    input_bytes = six.BytesIO(message.as_bytes())
    output_bytes = six.BytesIO()

    if recipients:  # we have recipients, so we encrypt

        # compute flags passed to encrypt/encrypt_sign
        flags = 0
        if always_trust is True:
            flags |= gpgme.ENCRYPT_ALWAYS_TRUST

        # sign message
        if context.signers:
            context.encrypt_sign(recipients, flags, input_bytes, output_bytes)
        else:
            context.encrypt(recipients, flags, input_bytes, output_bytes)
        output_bytes.seek(0)

        # the control message
        control_msg = MIMEApplication(_data='Version: 1\n', _subtype='pgp-encrypted',
                                      _encoder=encode_noop)
        control_msg.add_header('Content-Description', 'PGP/MIME version identification')
        del control_msg['MIME-Version']

        encrypted = MIMEApplication(_data=output_bytes.getvalue(),
                                    _subtype='octed-stream', name='encrypted.asc',
                                    _encoder=encode_noop)
        encrypted.add_header('Content-Description', 'OpenPGP encrypted message')
        encrypted.add_header('Content-Disposition', 'inline; filename="encrypted.asc"')
        del encrypted['MIME-Version']

        msg = MIMEMultipart(_subtype='pgp-encrypted', _subparts=[control_msg, encrypted])
        msg.set_param('protocol', 'application/pgp-encrypted')
        return msg
    else:  # just signing
        context.sign(input_bytes, output_bytes, gpgme.SIG_MODE_DETACH)
        output_bytes.seek(0)
        signature = output_bytes.getvalue()

        with open('message', 'wb') as fp:
            fp.write(message.as_bytes())
        with open('message.sig', 'wb') as fp:
            fp.write(signature)

        sig = MIMEBase(_maintype='application', _subtype='pgp-signature', name='signature.asc')
        sig.set_payload(signature)
        sig.add_header('Content-Description', 'OpenPGP digital signature')
        sig.add_header('Content-Disposition', 'attachment; filename="signature.asc"')
        del sig['MIME-Version']
        del sig['Content-Transfer-Encoding']

        msg = MIMEMultipart(_subtype='signed', _subparts=[message, sig])
        msg.set_param('protocol', 'application/pgp-signature')
        return msg
