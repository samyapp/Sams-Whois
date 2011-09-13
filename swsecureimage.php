<?php
session_start();
require_once(dirname(__FILE__).'/samswhois/secureimagecode.class.php');


$secure = new secureimagecode();
$img = $secure->GenerateImage();
header("content-type: image/png");
imagepng($img);
exit();
?>
