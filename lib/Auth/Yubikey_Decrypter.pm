package Auth::Yubikey_Decrypter;

use warnings;
use strict;
use Crypt::Rijndael;

=head1 NAME

Auth::Yubikey_Decrypter - The great new Auth::Yubikey_Decrypter!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

The decryption module does only one thing - decrypt the AES encrypted OTP from the Yubikey.  To this, it
requires the OTP, and the AES key.

Please note - this module does not perform authentication - it is a required component to decrypt the token first before authentication can be performed.

	#!/usr/bin/perl

	use strict;
	use Auth::Yubikey_Decrypter;

	my $fulltoken   = "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh";
	my $aeskey      = "ecde18dbe76fbd0c33330f1c354871db";

	my ($publicID,$secretid_hex,$counter_dec,$timestamp_dec,$session_use_dec,$random_dec,$crc_dec,$crc_ok) =
        	Auth::Yubikey_Decrypter::yubikey_decrypt($fulltoken,$aeskey);

	print "publicID  : $publicID\n";
	print "Secret id : $secretid_hex\n";
	print "Counter   : $counter_dec\n";
	print "Timestamp : $timestamp_dec\n";
	print "Session   : $session_use_dec\n";
	print "Random    : $random_dec\n";
	print "crc       : $crc_dec\n";
	print "crc ok?   : $crc_ok\n";

=head1 FUNCTIONS

=head2 yubikey_decrypt

Input : token aeskey

Token - received by the Yubikey
aeskey - either the modhex or hex AES key for your Yubikey (contact Yubico if you don't have the AES key)

=head1 REQUIRES

Perl 5, Crypt::Rijndael

Order your Yubikey from L<http://www.yubico.com>

=cut

sub yubikey_decrypt
{
        my $fulltoken   = $_[0];
        my $aeskey      = $_[1];
        my $aeskey_hex;
        if($aeskey =~ /^[a-f0-9]+$/i)
        {
                $aeskey_hex     = $aeskey;
        }
        elsif($aeskey =~ /^[cbdefghijklnrtuv]+$/i)
        {
                $aeskey_hex     = &yubikey_modhex_decode($aeskey);
        }
        else
        {
                die "A weird AES key was supplied.  Please provide only hex or modhex.";
        }

        # Convert the AES key from it's hex value to binary
        my $aeskey_bin  = &yubikey_hex2bin($aeskey_hex);

        # strip out the actual token
        my $publicID = substr($fulltoken,0,length($fulltoken)-32);
        my $token = substr($fulltoken,length($fulltoken)-32);

        # decode the token from modhex down to binary
        my $token_bin = &yubikey_modhex_decode($token);

        # Decrypt the token using it's key
        my $cipher = Crypt::Rijndael->new( $aeskey_bin );
        my $token_decoded_bin = $cipher->decrypt($token_bin);

        # Convert the token to hex - ** This step could be skipped if we can strip out the values
        #                               directly from the binary value **
        my $token_decoded_hex = &yubikey_bin2hex($token_decoded_bin);

        # get all the values from the decoded token
        my $secretid_hex        = substr($token_decoded_hex,0,12);
        my $counter_dec         = ord(substr($token_decoded_bin,7,1))*256+ord(substr($token_decoded_bin,6,1));
        my $timestamp_dec       = ord(substr($token_decoded_bin,10,1))*65536+ord(substr($token_decoded_bin,9,1))*256+ord(substr($token_decoded_bin,8,1));
        my $session_use_dec     = ord(substr($token_decoded_bin,11,1));
        my $random_dec          = ord(substr($token_decoded_bin,13,1))*256+ord(substr($token_decoded_bin,12,1));
        my $crc_dec             = ord(substr($token_decoded_bin,15,1))*256+ord(substr($token_decoded_bin,14,1));
        my $crc_ok              = &yubikey_crc_check($token_decoded_bin);

        return ($publicID,$secretid_hex,$counter_dec,$timestamp_dec,$session_use_dec,$random_dec,$crc_dec,$crc_ok);
}

=head1 AUTHOR

Phil Massyn, C<< <massyn at gmail.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-auth-yubikey_decrypter at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Auth-Yubikey_Decrypter>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Auth::Yubikey_Decrypter


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Auth-Yubikey_Decrypter>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Auth-Yubikey_Decrypter>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Auth-Yubikey_Decrypter>

=item * Search CPAN

L<http://search.cpan.org/dist/Auth-Yubikey_Decrypter>

=back


=head1 ACKNOWLEDGEMENTS


=head1 COPYRIGHT & LICENSE

Copyright 2008 Phil Massyn, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

sub yubikey_modhex_decode
{
        my $mstring = $_[0];
        my $cset="cbdefghijklnrtuv";
        my $decoded="";
        my $hbyte=0;
        my $pos;
        for (my $i=0; $i<length($mstring);$i++)
        {
                $pos=index($cset,substr($mstring,$i,1));
                if ($i/2 != int($i/2))
                {
                        $decoded .= chr($hbyte+$pos);
                        $hbyte=0;
                }
                else
                {
                        $hbyte=$pos*16;
                }
        }
        return $decoded;
}

sub yubikey_hex2bin
{
        my $in = $_[0];
        my $out = "";
        for(my $k=0;$k<length($in);$k+=2)
        {
                $out .= chr(hex(substr($in,$k,2)));
        }
        return $out;
}

sub yubikey_bin2hex
{
        my $in = $_[0];
        my $out = "";
        for(my $k=0;$k<length($in);$k++)
        {
                $out .= sprintf("%2x",ord(substr($in,$k,1)));
        }
        $out =~ s/ /0/g;        # this is a hack.. not sure why it has to be like this...
        return $out;
}

sub yubikey_crc_check
{
        my $buffer = $_[0];
        my $m_crc=0xffff;
        my $j;
        for(my $bpos=0; $bpos<16; $bpos++)
        {
                $m_crc ^= ord(substr($buffer,$bpos,1)) & 0xff;
                for (my $i=0; $i<8; $i++)
                {
                        $j=$m_crc & 1;
                        $m_crc >>= 1;
                        if ($j)
                        {
                                $m_crc ^= 0x8408;
                        }
                }
        }
        return $m_crc==0xf0b8;

        return 0;
}

1; # End of Auth::Yubikey_Decrypter
