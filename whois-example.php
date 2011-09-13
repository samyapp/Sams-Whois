<?php 

/* 

File: whois-example.php
Purpose: heavily commented example of using the sams whois php scripts to include a whois lookup service on
your own website.

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

	Read the comments and change the variables to alter the behaviour of the SamsWhois script.

*/

/*
	To Require the user to enter a randomly generated "security" code for each lookup
	set $swSecure = true;

	This works by generating a random code each time the lookup form is displayed,
	storing it in a session variable, displaying an image containing the code and asking
	the user to enter the code displayed when they submit the lookup form. The code they
	enter is then compared with the generated code and if they match, then the lookup is done.

	Its purpose is to stop people from abusing your whois lookup script through scripting
	100's or 1000's of lookups per minute, and possibly getting you banned for excessive 
	lookups.

	You MUST uncomment the code "session_start();" code for this to work.

	You MUST upload the swsecureimage.php file to your document root (so it can be 
	accessed at http://www.yoursite.com/swsecureimage.php). This is the file that
	generates the image.

	Your server MUST have the php gd image module active for this to work.

	You MUST make sure that the $m_font variable contains the FULL path to the ttf font to
	use to create the image. By default, a font should be included with this script and this
	variable should already be set for you.
	
	Additional options (font, size, number of characters, whether to use lower and upper
	case characters, and settings for the extra paranoid can be modified by editing the
	variables at the top of the secureimagecode.class.php file.

*/

/* you line below must be uncommented if using the secure code image option */
//session_start();
$swSecure = false;

/* 
	Whois lookup result caching.
	Set $swCacheLifetime to a positive integer to cache the results of each lookup 
	that number of minutes.

	When caching is turned on, the script stores the whois data obtained from each
	lookup for the specified number of minutes. If a user tries to lookup the domain
	within the cache lifetime, the stored data is displayed instead of the script looking
	up the domain again.

	The benefits of this are less usage of your server's resources and bandwidth, as well
	as less queries to the whois servers.

	The folder /samswhois/cache MUST have the correct permissions for the script to create files in it.

*/

$swCacheLifetime = 0;

/*
	"Cleaning" whois output. Removes extraneous text from the whois result.
	This will only make a difference for results from whois servers
	that the /samswhois/config.txt file contains a cleanup setting for.

	Possible options for $swClean are:

	$swClean = 'off'; Display the whois data "as-is".
	$swClean = 'on'; Always remove extraneous text from the whois result.
	$swClean = 'optional'; Allow the user to turn cleaning on or off via a checkbox.

*/

$swClean = 'optional';

/*
	Hi-lighting specific rows in the whois data, eg. expiration date, status, etc.
	This only hilights the results if the /samswhois/config.txt file contains hilite 
	settings for that whois server.

	Possible values for $swHilite are:

	$swHilite = 'off'; No hilighting.
	$swHilite = 'on'; Always hilight results.
	$swHilite = 'optional'; Let the user check a checkbox if they want to use hi-lighting.

*/

$swHilite = 'optional';

/*
	Check authorative server for .com & .net domains.

	Set $swAuth = true; to check the authoriative whois server for domains in the com and net extension.

	Set $swOnlyShowAuth = true; to only display the result from the authoritative server, not the registry server
	in cases where it is available.

*/

$swAuth = true;
$swOnlyShowAuth = false;

/*
	Tld options:

	Limit the tlds that the script will do whois lookups for by setting the $swTlds variable
	to a comma separated list of tlds to accept, eg. $swTlds = 'com,net,org'.

	Setting $swTlds = '' will result in the script looking up all the tlds
	defined in the /samswhois/config.txt file.

	Set $swListTlds = true; to list the tlds supported underneath the form.

	Set $swTldOptions = true; to let the user select the tld to lookup from
	a drop-down <select> menu.

	Set $swAlphabeticalTlds = true; to display the tlds alphabetically.
	If $swAlphabeticalTlds = false; then the tlds will be listed in the order they are
	contained in the /samswhois/config.txt file, or in the order they are listed in the $swTlds variable.

*/

$swTlds = '';

$swListTlds = false;

$swTldOptions = true;

$swAlphabeticalTlds = false;

/*
	Text, messages, and other stuff that is displayed.

	Add the following variables to this script along with your custom messages to
	override the defaults in the samswhois.inc.php file.

	// The label that appears on the whois lookup form submit button
	$swSubmitLabel = 'Lookup Domain';

	// The instructions displayed below the whois lookup form
	$swInstructions = 'Enter a domain and click "lookup"';

	// Message displayed asking users to enter the security code (only displayed if $swSecure = true)
	$swSecurityMessage = 'Enter the 4 digit code.';

	// Text that says what server the lookup was from. The value {server} will be replaced by the actual server name.
	$swServerText = 'whois lookup at {server}...';

	// Message displayed if the domain name is available. The values {domain}, {sld}, {tld} will be replaced.
	$swAvailableMessage = '{domain} is <span style="color: green;">Available.</span>';

	// Message displayed if the domain name is registered. The values {domain}, {sld}, {tld} will be replaced.
	$swRegisteredMessage = '{domain} is <span style="color: red;">Registered.</span>';

	// Error message displayed if the user submits the form without entering the correct security code (if required)
	$swSecurityError = 'For security purposes you MUST enter the 4-digit code shown above.';

	// Error message displayed if the whois lookup fails.
	$swLookupError = 'Sorry, an error occurred.';

	// Error message displayed if the user enters an unsupported tld
	$swTldError = 'Sorry, {tld} is not supported.';

	// Error message displayed if an error occurs during the lookup
	$swLookupError = 'An error occurred with the whois lookup.';

	// Heading text displayed above the form...
	$swHeadingText = 'Whois Lookup';

*/

// Message displayed if the domain name is available. The values {domain}, {sld}, {tld} will be replaced.
$swAvailableMessage = '{domain} is <span style="color: green;">Available.</span>';

// Message displayed if the domain name is registered. The values {domain}, {sld}, {tld} will be replaced.
$swRegisteredMessage = '{domain} is <span style="color: red;">Registered.</span>';

$swSubmitLabel = '>>';

/*

	$swOnlyShowAvailability

	Set to true to only display the domain status (no whois data)

	If setting this to true, you should also set $swAuth (described above) to false
	because there is no point doing the additional lookup if you're not displaying the
	whois data

	For the same reason, you should also set $swHilite = "off"; and $swClean = "off",
	as if you are not displaying the whois data, there is not point giving your site user
	the option to hilight or clean it :)

*/

$swOnlyShowAvailability = false;

/* 
	You can set the default domain name sld and tld to display when the page is first displayed.

	$swDefaultSld = 'domain'; // NOTE: should just be the sld, no extension
	$swDefaultTld = 'com';	// NOTE: No . at the beginning of the tld.

*/

$swDefaultSld = 'domain';
$swDefaultTld = 'com';

?>
<!-- beginning of html page header - replace the html below with your own -->
<html>
<head>
<title>Sams Whois Lookup</title>

<!-- 
	links in the css stylesheet used to set the design of the whois lookup form and whois result
	see the file swstyles.css for comments on what each style affects.
-->
<link rel="stylesheet" type="text/css" href="swstyles.css" />

</head>
<body style="font-family: verdana, arial; font-size: 10pt; margin-top: 100px;">

<!-- end of the html page header, back to php to include the samswhois file... -->
<?php

/*
	The line below includes the samswhois.inc.php script which does everything else for us,
	including generating the whois lookup form, displaying the secure code image if required,
	doing the whois lookup and displaying the result. Isn't that nice of it.
*/

require_once(dirname(__FILE__).'/samswhois/samswhois.inc.php');

?>
<!-- beginning of html page footer - replace the html below with your own -->
</body>
</html>
<!-- end of page. You can stop reading now. You don't really have much choice in the matter =) -->