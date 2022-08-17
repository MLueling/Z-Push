<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * Description of NewTokenData
 *
 * @author Matthias Lueling
 */
class NewTokenData {
    public $token_type; // string
    public $expires_in; // int
    public $expiration_utc; // string
    public $access_token; // string
    public $refresh_token; // string
}
