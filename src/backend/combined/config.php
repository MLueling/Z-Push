<?php
/***********************************************
* File      :   backend/combined/config.php
* Project   :   Z-Push
* Descr     :   configuration file for the
*               combined backend.
*
* Created   :   29.11.2010
*
* Copyright 2007 - 2016 Zarafa Deutschland GmbH
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License, version 3,
* as published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* Consult LICENSE file for details
************************************************/

class BackendCombinedConfig {

    // *************************
    //  BackendCombined settings
    // *************************
    /**
     * Returns the configuration of the combined backend
     *
     * @access public
     * @return array
     *
     */
    public static function GetBackendCombinedConfig() {
        //use a function for it because php does not allow
        //assigning variables to the class members (expecting T_STRING)
        return array(
            //the order in which the backends are loaded.
            //login only succeeds if all backend return true on login
            //sending mail: the mail is sent with first backend that is able to send the mail
            'backends' => array(
//                'i' => array(
//                    'name' => 'BackendIMAP',
//                ),
//                'z' => array(
//                    'name' => 'BackendZarafa',
//                ),
//                'm' => array(
//                    'name' => 'BackendMaildir',
//                ),
//                'v' => array(
//                    'name' => 'BackendVCardDir',
//                ),
                'c' => array(
                    'name' => 'BackendOnlineakte',
                ),
//                'z' => array(
//                    'name' => 'BackendKopano',
//                ),
//                'l' => array(
//                    'name' => 'BackendLDAP',
//                ),
//                'd' => array(
//                    'name' => 'BackendCardDAV',
//                ),
//                'c' => array(
//                    'name' => 'BackendCalDAV',
//                ),
            ),
            'delimiter' => '/',
            //force one type of folder to one backend
            //it must match one of the above defined backends
            'folderbackend' => array(
                SYNC_FOLDER_TYPE_INBOX => 'c',
                SYNC_FOLDER_TYPE_DRAFTS => 'c',
                SYNC_FOLDER_TYPE_WASTEBASKET => 'c',
                SYNC_FOLDER_TYPE_SENTMAIL => 'c',
                SYNC_FOLDER_TYPE_OUTBOX => 'c',
                SYNC_FOLDER_TYPE_TASK => 'c',
                SYNC_FOLDER_TYPE_APPOINTMENT => 'c',
                SYNC_FOLDER_TYPE_CONTACT => 'c',
                SYNC_FOLDER_TYPE_NOTE => 'c',
                SYNC_FOLDER_TYPE_JOURNAL => 'c',
                SYNC_FOLDER_TYPE_OTHER => 'c',
                SYNC_FOLDER_TYPE_USER_MAIL => 'c',
                SYNC_FOLDER_TYPE_USER_APPOINTMENT => 'c',
                SYNC_FOLDER_TYPE_USER_CONTACT => 'c',
                SYNC_FOLDER_TYPE_USER_TASK => 'c',
                SYNC_FOLDER_TYPE_USER_JOURNAL => 'c',
                SYNC_FOLDER_TYPE_USER_NOTE => 'c',
                SYNC_FOLDER_TYPE_UNKNOWN => 'c',
            ),
            //creating a new folder in the root folder should create a folder in one backend
            'rootcreatefolderbackend' => 'c',
        );
    }
}
