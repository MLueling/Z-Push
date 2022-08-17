<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * @abstract Helper class for token aquiration from the AdvoNet  Security Gateway
 * @author Matthias Lueling
 */

class IdentityHMAC
{
    public $AppID;
    public $Kanzlei;
    public $Database;
    public $User;
    public $Role;
    public $Product;
    public $Password;
    public $Nonce;
    public $HMAC512Signature;
    public $RequestTimeStamp;

    public function Sign(string $apiKey) : string {
        // Fills Nonce + RequestTimeStamp and then HMAC512Signature with the signature
        // and returns a json serialized string of the whole object
        $objDateTime = new DateTime('NOW');
        $objDateTime = $objDateTime->setTimezone(new DateTimeZone("UTC"));
        $this->RequestTimeStamp = $objDateTime->format(DateTime::ISO8601);
        $this->Nonce = uniqid();
        $dataToSign = sprintf("%s:%s:%s:%s", $this->Product, $this->AppID, $this->Nonce, $this->RequestTimeStamp);
        $this->HMAC512Signature = base64_encode(hash_hmac('sha512', utf8_encode($dataToSign), base64_decode($apiKey), true));
        return json_encode($this);
    }
}