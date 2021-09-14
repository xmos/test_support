#!/usr/bin/perl
# Copyright 2016-2021 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
use warnings;
use strict;

use Carp;
use SetupEnv;
use File::Copy;
use File::Path;
use XmosBuildLib;
use XmosArg;
use Carp;

my $xmosArg;

my $MAKE_FLAGS;
my $CONFIG;
my $DOMAIN;
my $BIN;

my %ALIASES =
  (
    'all' => [ 'install' ]
  );

my %TARGETS =
  (
    'install'   => [ \&DoInstall,   "Install" ],
  );

sub main
{
  $xmosArg = XmosArg::new(\@ARGV);
  SetupEnv::SetupPaths();

  my @targets =
    sort { XmosBuildLib::ByTarget($a, $b) }
      (@{ $xmosArg->GetTargets() });

  $MAKE_FLAGS = $xmosArg->GetMakeFlags();
  $DOMAIN = $xmosArg->GetOption("DOMAIN");
  $CONFIG = $xmosArg->GetOption("CONFIG");
  $BIN = $xmosArg->GetBinDir();

  foreach my $target (@targets) {
    DoTarget($target);
  }
  return 0;
}

sub DoTarget
{
  my $target = $_[0];
  if ($target eq "list_targets") {
    ListTargets();
  } else {
    my $targets = $ALIASES{$target};
    if (defined($targets)) {

      # Target is an alias
      foreach my $target (@$targets) {
        DoTarget($target);
      }
    } else {
      my $function = $TARGETS{$target}[0];
      if (defined($function)) {
        print(" ++ $target\n");
        &$function();
      }
    }
  }
}

sub ListTargets
{
  foreach my $target (keys(%TARGETS)) {
    print("$target\n");
  }
  foreach my $alias (keys(%ALIASES)) {
    print("$alias\n");
  }
}

sub PrintUsage
{
  my $target;
  my $alias;
  my $targets;
  my $targetTable;
  my $description;

  print("Usage:\n");
  print("   Build.pl targets\n");
  print("\n");
  print("   Available targets:\n");
  while (($target, $targetTable) = each(%TARGETS)) {
    $description = @$targetTable[1];
    print("   $target - $description\n");
  }
  while (($alias, $targets) = each(%ALIASES)) {
    $description = "does";
    foreach $target (@$targets) {
      $description = "$description \'$target\' ";
    }
    print("   $alias - $description\n");
  }
  print("   list_targets - List all targets\n");
  exit(1);
}

sub DoInstall
{
  XmosBuildLib::InstallDirectory($DOMAIN, "", "lib/python", "");
  XmosBuildLib::InstallReleaseDirectory($DOMAIN, "", "lib/python", "");
}

main()
