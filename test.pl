// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2009-2018 Bitcoin Developers
// Copyright (c) 2019 The Veil Developers
/*
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
*/
#!/usr/bin/perl

use threads;
use threads::shared;
use bytes;
use IO::Socket;
use strict;

my @dom = ("seed","bitcoin","sipa","be");

my $run :shared = 1;

sub go {
  my ($idx) = @_;

  my $runs = 0;
  
  my $sock = IO::Socket::INET->new(
    Proto    => 'udp',
    PeerPort => 53,
    PeerAddr => "vps.sipa.be",
  ) or die "Could not create socket: $!\n";

  while($run) {

    my $id = int(rand(65536));
    my $qr = 0;
    my $opcode = 0;
    my $aa = 0;
    my $tc = 0;
    my $rd = 0;
    my $ra = 0;
    my $z = 0;
    my $rcode = 0;
    my $qdcount = 1;
    my $ancount = 0;
    my $nscount = 0;
    my $arcount = 0;
    my $header = pack('nnnnnn',$id,1*$qr + 2*$opcode + 32*$aa + 64*$tc + 128*$rd + 256*$ra + 512*$z + 4096*$rcode, $qdcount, $ancount, $nscount, $arcount);
    my $qtype = 1; # A record
    my $qclass = 1; # IN class
    my $query = (join("", map { chr(length($_)) . $_ } (@dom,""))) . pack('nn',$qtype,$qclass);
    my $msg = $header . $query;
    $sock->send($msg);
    my $resp;
    $runs++ if ($sock->recv($resp, 512, 0));
    
#    $sock->close();
  }
  return $runs;
}

my @threads;

for my $i (0..500) {
  $threads[$i] = threads->create(\&go, $i);
}

sleep 10;

$run=0;
my $runs = 0;
foreach my $thr (@threads) {
  $runs += $thr->join();
}

print "$runs runs\n";
