package Net::NiftyCloud::mBaaS;
use strict;
use warnings;
use Time::HiRes qw/ gettimeofday /;
use HTTP::Request;
use LWP::UserAgent;
use JSON::PP;

use Digest::SHA qw/ hmac_sha256_base64 /;
{
  $Net::NiftyCloud::mBaaS::VERSION = '0.1';
}

sub new {
    my $class = shift;
    my %args  = @_;
    my $obj = bless {}, $class;
    my $method = $args{ method } || 'GET';
    $obj->{ method } = uc( $method );
    $obj->{ endpoint } = $args{ endpoint } || 'mb.api.cloud.nifty.com';
    $obj->{ application_key } = $args{ application_key };
    $obj->{ client_key } = $args{ client_key };
    $obj->{ timestamp } = $args{ timestamp } || $obj->get_utc();
    $obj->{ version } = $args{ version } || '2013-09-01';
    if ( exists( $args{ ssl_opt } ) ) {
        $obj->{ ssl_opt } = $args{ ssl_opt };
    }
    $obj;
}

sub request {
    my ( $obj, $path, $params ) = @_;
    my $signature = $obj->get_signature( $path );
    my $api = 'https://' . $obj->{ endpoint };
    if ( $path && ( $path !~ m!^\/! ) ) {
        $path = '/' . $path;
    }
    $path = '/' . $obj->{ version } . $path;
    $api .= $path;
    my $req = HTTP::Request->new( $obj->{ method }, $api );
    $req->header( 'X-NCMB-Application-Key' => $obj->{ application_key },
                  'X-NCMB-Signature' => $signature,
                  'X-NCMB-Timestamp' => $obj->{ timestamp },
                  'Content-Type' => 'application/json' );
    if ( defined $params ) {
        my $json = encode_json( $params );
        $req->content( $json );
    }
    my $ua = LWP::UserAgent->new();
    if ( exists( $obj->{ ssl_opt } ) ) {
        $ua->ssl_opts( @{ $obj->{ ssl_opt } } );
    }
    my $res = $ua->request( $req );
    $res;
}

sub get_utc {
    my $obj = shift;
    my ( $epocsec, $ms ) = gettimeofday();
    $ms = '000000' unless $ms;
    $ms = substr( $ms, 0, 3 );
    my @tl = gmtime( time );
    my $ts = sprintf '%04d-%02d-%02dT%02d:%02d:%02d', $tl[5]+1900, $tl[4]+1, @tl[3,2,1,0];
    $ts .= '.' . $ms . 'Z';
    $ts;
}

sub get_date {
    my $obj = shift;
    my $ts = shift;
    if (! $ts ) {
        $ts = $obj->get_utc();
    }
    # {"__type": "Date", "iso": "yyyy-mm-ddTHH:MM:ss.SSSZ"}
    return { '__type' => 'Date', 'iso' => $ts };
}

sub get_signature {
    my ( $obj, $path ) = @_;
    my $query;
    if ( $path && ( $path !~ /^\// ) ) {
        $path = '/' . $path;
    }
    if ( $path && ( $path =~ /\?/ ) ) {
        my @paths = split( /\?/, $path );
        $path = $paths[ 0 ];
        $query = $paths[ 1 ];
    }
    $path = '/' . $obj->{ version } . $path;
    my $endpoint = $obj->{ endpoint };
    my $application_key = $obj->{ application_key };
    my $client_key   = $obj->{ client_key };
    my $timestamp = $obj->{ timestamp };
    my %headers;
    $headers{ 'SignatureMethod' } = 'HmacSHA256';
    $headers{ 'SignatureVersion' } = '2';
    $headers{ 'X-NCMB-Application-Key' } = $application_key;
    $headers{ 'X-NCMB-Timestamp' } = $timestamp;
    my $param = '';
    for my $key ( sort keys %headers ) {
        $param .= '&' if $param;
        $param .= $key . '=' . $headers{ $key };
    }
    $param .= '&' . $query if $query;
    my $method = $obj->{ method };
    my $str_to_sign = $method . "\n" . $endpoint . "\n" . $path . "\n" . $param;
    my $signature = hmac_sha256_base64( $str_to_sign, $client_key );
    while ( length( $signature ) % 4 ) {
        $signature .= '=';
    }
    return $signature;
}

1;

__END__

=head1 NAME

Net::NiftyCloud::mBaaS - Client for NIFTY Cloud mobile backend.

=head1 SYNOPSIS

    my @ssl_opt = ( verify_hostname => 0 );
    my %args = (
        method => 'GET',
        application_key => '6145f91061916580c742f806bab67649d10f45920246ff459404c46f00ff3e56',
        client_key => '1343d198b510a0315db1c03f3aa0e32418b7a743f8e4b47cbff670601345cf75',
        timestamp => '2013-12-02T02:44:35.452Z',
        ssl_opt => \@ssl_opt,
    );
    my $client = Net::NiftyCloud::mBaaS->new( %args );

=head1 METHODS

=head2 get_signature

Create a signature for API Request.

http://mb.cloud.nifty.com/doc/current/rest/common/signature.html

    my $path = 'classes/TestClass?where=%7B%22testKey%22%3A%22testValue%22%7D';
    my $signature = $client->get_signature( $path );

=head2 get_utc

Get current timestamp.

    my $timestamp = $client->get_utc();
    
    # 2017-03-10T06:23:19.297Z

=head2 get_date

Get Date type object like { __type => Date, 'iso => 'yyyy-mm-ddTHH:MM:ss.SSSZ' }.
Omitting the timestamp, Creates the object from current timestamp.

http://mb.cloud.nifty.com/doc/current/rest/common/format.html#%E6%97%A5%E4%BB%98

    my $date = $client->get_date( '2017-03-10T06:23:19.297Z' );

=head2 request

Send API Request with path and params. return HTTP::Response object.

    my my $path = 'installations?limit=10';
    my $res = $client->request( $path );
    if ( $res->is_error ) {
       die $res->status_line;
    }
    print $res->content;

=head1 AUTHOR

Junnama Noda <junnama@alfasado.jp>

=head1 COPYRIGHT

Copyright (C) 2017, Junnama Noda.

=head1 LICENSE

This program is free software;
you can redistribute it and modify it under the same terms as Perl itself.

=cut
