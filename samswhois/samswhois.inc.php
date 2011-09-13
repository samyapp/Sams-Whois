<?php
/*

File: samswhois.inc.php
Purpose: simple interface to using the samswhois.class.php file

Copyright (c) 2004, 2008 Sam Yapp
http://www.phpace.com/scripts/sams-whois

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

/***********************************************
	Section 1 - Initialization...
************************************************/

/*
	include the samswhois class file. You can use this class directly in your scripts if you want
	more control...
*/

require_once(dirname(__FILE__).'/samswhois.class.php');

/* create a new samswhois object */

$whois = new SamsWhois();

/*
	initialize any of the variables that we use. 
	You can set any of these values in the script that includes this one to override
	the values below.
*/

if( !isset($swHilite) ) $swHilite = 'no';	// hilight fields in the whois output (eg. status, nameservers, etc)
if( !isset($swClean) ) $swClean = 'no';	// "clean" the whois output of extraneous text
if( !isset($swAuth) ) $swAuth = true;	// check the authoritative whois server for com & net
if( !isset($swOnlyShowAuth) ) $swOnlyShowAuth = false;	// if checking authoritative, should we ignore the registry whois?
if( !isset($swSecure) ) $swSecure = false;	// generate a security code for each whois lookup
if( !isset($swListTlds) ) $swListTlds = false;	// list the supported tlds underneath the lookup form
if( !isset($swTldOptions) ) $swTldOptions = false;	// let the user select the tld from a drop-down list
if( !isset($swAlphabeticalTlds) ) $swAlphabeticalTlds = false;	// list tlds alphabetically?
if( !isset($swTlds) ) $swTlds = '';	// limit the tlds supported to those in a comma separated list eg 'com,net,org'
if( !isset($swDefaultTld) ) $swDefaultTld = 'com';	// the default tld to use / display in the form
if( !isset($swDefaultSld) ) $swDefaultSld = 'domain';	// the default sld to display in the form
if( !isset($swCacheLifetime ) ) $swCacheLifetime = 0; // the length of time in minutes to cache whois lookup results
if( !isset($swOnlyShowAvailability) ) $swOnlyShowAvailability = false;	// only show availability, no whois data

/*
	initialize any messages to display that aren't already set in the script that includes this one
*/

if( !isset($swSubmitLabel) ) $swSubmitLabel = 'Check Domain';	// the submit button label for the whois form

if( !isset($swInstructions) ){		// instructions displayed under the form - differ slightly if the user can choose the tld
	if( $swTldOptions ){
		$swInstructions = 'Enter a domain name and select a tld from the box above.';
	}else{
		$swInstructions = 'Enter a domain name including extension in the box above.';
	}
}

if( !isset($swSecurityError) ){	// error message displayed if the user doesn't enter the security code when required
	$swSecurityError = 'For security reasons, you MUST enter the 4 digit code shown above.';
}

if( !isset($swLookupError) ){	// error message displayed if a whois lookup query fails
	$swLookupError = 'Sorry, an error occurred.';
}

if( !isset($swSecurityMessage) ){	// message displayed below the form when a security code is required
	$swSecurityMessage = 'For security purposes, please also enter the 4 digit code.';
}

if( !isset($swTldError) ){	// message displayed if the user enters a tld that is not supported
	$swTldError = 'Sorry, that tld is not supported.';
}

if( !isset($swHeadingText) ){ // displayed above the form - could replace with a logo image or the name of your site
	$swHeadingText = 'Whois Lookup';
}

/*
	Set any variables in the SamsWhois class that have been set in the script that includes this one.
*/

$whois->SetCacheLifetime($swCacheLifetime);

if( isset($swAvailableMessage) ){	// the message displayed when $whois->GetStatusText() is called and the domain is available
	$whois->SetAvailableMessage($swAvailableMessage);
}

if( isset($swRegisteredMessage) ){ // message displayed when $whois->GetStatusText() is called and the domain is registered
	$whois->SetRegisteredMessage($swRegisteredMessage);
}

if( isset($swServerText) ){	// message displayed when $whois->GetServerText() is called - {server} is replaced by the server name
	$whois->SetServerText($swServerText);
}

if( isset($swAuth) && $swAuth == true ){ // tell the script whether to lookup com & net at the authoratitive server
	$whois->m_redirectauth = true;
}

/*
	Security code image
	if we are using a secure image code, include the class and create a secureimagecode object for later use
*/

if( $swSecure ){

	require_once(dirname(__FILE__).'/secureimagecode.class.php');

	$secure = new secureimagecode();
}

/*
	limit the tlds to use (if set in the script that includes this one)
	$swTlds should be in the form 'com,net,org' where the tlds are the ones to use.
*/

if(  $swTlds != '') $whois->SetTlds($swTlds);

/*
	Initialize some variables used in the rest of the script
*/

$tld = $swDefaultTld;	// the tld
$sld = $swDefaultSld;	// the sld
$domain = '';	// this will be displayed as the value of the domain <input> in the form - it is set later on
$nocode = false;	// will be set to true later if the user submits the form without a correct security code (if required)
$dolookup = false;	// set later if the lookup form has been submitted with a valid domain / tld.

/*
	Determine whether to automatically clean whois output. If $swClean = 'optional', checks if the user wants this.
*/

switch( $swClean ){
	case 'yes': $sw_clean = true; break;
	case 'optional': $sw_clean = isset($_REQUEST['clean']) ? true : false; break;
	default: $sw_clean = false; break;
}

/*
	Determine whether to hilight certain rows of the whois output. If $swHilite = 'optional', checks if the user wants this.
*/

switch( $swHilite ){
	case 'yes': $sw_hilite = true; break;
	case 'optional': $sw_hilite = isset($_REQUEST['hilite']) ? true : false; break;
	default: $sw_hilite = false; break;
}

/*
	Check if the user has submitted the lookup form
*/

if( isset($_REQUEST['lookup']) && isset($_REQUEST['domain'])){

	$dn = trim($_REQUEST['domain']);

	if( $dn != '' ){

		// separate the sld and tld, checking for a submitted tld if $swTldOptions = true
		$dot = strpos($dn, '.');
		if( $dot !== false ){
			$sld = substr($dn, 0, $dot);
			$tld = substr($dn, $dot+1);
		}else{
			$sld = $dn;
			if( $swTldOptions && isset($_REQUEST['tld']) ) $tld = trim($_REQUEST['tld']);
		}

		$domain = $sld.'.'.$tld;

		if( $whois->ValidDomain($domain) ){ // check that it is a valid domain
			$dolookup = true;

			if( $swSecure ){	// if we are using a secure code, check the user has entered it correctly
				if( !$secure->CheckCode($_REQUEST['code']) ){
					$nocode = true;
					$swErrorMessage = $swSecurityError;
					$dolookup = false;
				}
			}
		}else{
			$swErrorMessage = $swTldError;
		}
	}
}

/*
	Set the domain variable to the correct value (either with or without tld) for later output in the form
*/

if( $swTldOptions ){
	$domain = $sld;
}else{
	$domain = $sld.'.'.$tld;
}

/***********************************************
	Section 2 - Display the whois lookup form

	Depending on what options have been set in the calling script, the form may contain
	various messages, a drop-down box to select the tld, and checkboxes.

************************************************/

?>
<div class="swPositioner">
<br />
<form id="whoisform" name="whoisform" style="margin: 0px;" action="<?php echo $_SERVER['SCRIPT_NAME'];?>" method="get">
<div class="swForm">
<div class="swHeading"><?php echo $swHeadingText;?></div>
<?php
?>
<input type="text" name="domain" class="swDomain" value="<?php echo $domain;?>" onFocus="this.select();" />
<?php
	if( $swTldOptions){	// if listing tlds as a <select> box
?><b>.</b> <select class="swtld" name="tld"><?php echo $whois->TldOptions($tld,$swAlphabeticalTlds);?></select><?php
	}
	if( $swSecure ){ // should we get the user to enter a security code?
		$secure->GenerateCode();
?>
	<input type="text" class="swSecureCode" name="code" />
	<img align="absmiddle" src="swsecureimage.php" class="swSecureImage" />
<?php
	}
?>
<input type="submit" name="lookup" value="<?php echo $swSubmitLabel;?>" class="swSubmit" />
<div class="swInfo">
<?php
	if( $swClean == 'optional' ){ // if cleaning is optional, give the user the option...
?>
<input type="checkbox" name="clean" value="1" <?php if( $sw_clean ) echo 'CHECKED';?> />
<b>Clean whois output?</b>
<?php
	}
	if( $swHilite == 'optional' ){ // if whois output hilighting is optional, give the user the option...
?>
<input type="checkbox" name="hilite" value="1" <?php if( $sw_hilite ) echo 'CHECKED';?> />
<b>Hilight Important Fields?</b>
<?php
	}
	if( $swHilite == 'optional' || $swClean == 'optional' ) echo '<br />';
	echo $swInstructions;
if( $swListTlds){	// list all supported tlds.
	echo '<br />Supported Tlds: '.join(', ', $whois->GetTlds($swAlphabeticalTlds)).'.';
}
if( $swSecure ){	// display the message about the security code
	echo "<br />".$swSecurityMessage."<br />";
}
?>
</div>
<?php
	if( isset($swErrorMessage ) ){ 	// display any error messages...
?><div class="swError"><?php echo $swErrorMessage;?></div><?php
	}
?>
</div>
</form>
<!-- 
	a little bit of javascript that sets the keyboard focus to either the domain field,
	or the security code field if the user has just submitted the form without entering
	the correct value.
-->
<script language="JavaScript" type="text/javascript">
<!--
document.forms['whoisform'].<?php echo $nocode == true ? 'code' : 'domain';?>.focus();
//-->
</script>
<?php

/***********************************************
	Section 3 - Do the whois lookup
************************************************/

if( $dolookup == true ){ // form submitted, all ok

	if( $whois->Lookup($sld.'.'.$tld) ){ // do the lookup
?>
<div class="swResults">
<table style="border: 0px;" align="center">
<tr>
<td style="font-size: 10pt; font-family: verdana, arial;">
<div class="swStatus">
<?php 
	echo $whois->GetStatusText(); // display the domain's status 
?>
</div>
<?php
		/*
			Display the whois data, formatting it for display as html
			We pass the values for cleaning and hilighting whois output to the GetData() function.
			The number argument passed to the GetData() and GetServerText() functions indicates
			which lookup result we want for com and net domains where there may be an additional result
			from the authoratitive server.
		*/

		if( !$swOnlyShowAvailability ){

			$data = $whois->GetData(0, $swClean, $swHilite);
			if( $whois->GetServerCount() == 2 ){
				if( $swOnlyShowAuth ){
					$output = '<div class="swServer">'.$whois->GetServerText(1).'</div>'."\n";
					$output .='<div class="swData">'.nl2br($whois->GetData(1, $sw_clean, $sw_hilite)).'</div>'."\n";
				}else{
					$output = '<div class="swServer">'.$whois->GetServerText(1).'</div>'."\n";
					$output .='<div class="swData">'.nl2br($whois->GetData(1, $sw_clean, $sw_hilite)).'</div>'."\n";
					$output .= '<div class="swServer">'.$whois->GetServerText(0).'</div>'."\n";
					$output .='<div class="swData">'.nl2br($whois->GetData(0, $sw_clean, $sw_hilite)).'</div>'."\n";
				}
			}else{
				$output = '<div class="swServer">'.$whois->GetServerText(0).'</div>'."\n";
				$output .='<div class="swData">'.nl2br($whois->GetData(0, $sw_clean, $sw_hilite)).'</div>'."\n";
			}
			echo $output;
		}
	}else{
			// an error occurred with the whois lookup...
?>
<div class="swError">
<?php echo $swLookupError;?>
</div>
<?php
	}
?>
</td>
</tr>
</table>
<?php
}

// and thats it :)

?>
<div style="margin-top: 30px; text-align: center; font-size: 10px; color: #aaaaaa;">Powered by <a style="color: #aaaaaa; text-decoration: none;" target="_blank" href="http://whois.samscripts.com/">Sams Whois</a></div>
</div>