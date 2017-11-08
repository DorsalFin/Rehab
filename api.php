 <?php
require_once 'config.php';
require_once 'pgConnect.php';
require_once 'FileHandler.php';
require_once 'vuforia/vuforia.php';
require_once 'PayPalHandler.php';
require_once 'thingiverse/thingiverse.php';

require 'vendor/autoload.php';
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

class API
{
    public $arguments;
    public $currentUserId='-1';
    public $db;

    public $info_email_address = 'info@makersempire.com';
    public $support_email_address = 'info@makersempire.com';
    public $debug_email_address = 'roland@makersempire.com';
    public $application_name = 'Makers Empire';

    public $schoology_consumer_key = 'd11212b2dc2078d38ea510065288a7490561d187b';
    public $schoology_consumer_secret = '86fd0c30cc0945f0776131dd8b5e513f';

    public $scopeDefault = "-1";
    public $scopeClass = "1";
    public $scopeSchool = "2";
    public $scopeAllSchools = "3";
    public $scopeWorldwide = "4";


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    function NewUser()
    {
        $username = $this->getCleanValueFromArguments("username");
        $password = $this->getCleanValueFromArguments("password");

        $existing_user = $this->db->fetchValue("select id from users where username ilike '$username'");
        if ($existing_user)
        {
            $result["result"] = 0;
            $result["msg"] = "username already exists";
        }
        else
        {
            $hashed_password = md5($password);
            $sql = "insert into users (username, password) values ('$username', '$hashed_password')";
            $new_user_result = $this->db->exesql($sql);
            if (pg_affected_rows($new_user_result) > 0)
            {
                $last_id = $this->db->fetchValue("select lastval()");
                $result["result"] = 1;
                $result["user_id"] = $last_id;
                $result["username"] = $username;
            }
            else
            {
                $result["result"] = 0;
                $result["msg"] = "error inserting new user";
            }
        }

        return json_encode($result);
    }

    function LoginUser()
    {
        $username = $this->getCleanValueFromArguments("username");
        $password = $this->getCleanValueFromArguments("password");

        $existing_user = $this->db->fetchArray("select id, username, password, admin, account_expires from users where username ilike '$username'");
        if ($existing_user)
        {
            if ($existing_user["password"] == $password)
            {
                $result["result"] = 1;
                $result["username"] = $existing_user["username"];
                $result["user_id"] = $existing_user["id"];
                $result["admin"] = $existing_user["admin"];
                $result["expiry"] = $existing_user["account_expires"];

                // get user's best results for each game and each difficulty
                $gameNames = $this->db->sqlToArray("select unnest(enum_range(null::game_enum))");
                $userId = $existing_user["id"];
                for ($i = 0; $i < 3; $i++)
                {
                    for ($g = 0; $g < count($gameNames); $g++)
                    {
                        $gameName = $gameNames[$g]["unnest"];

                        if ($gameName == "pop_pop") continue;
                        if ($gameName == "basketball")
	                    $sql = "select array_upper(action_times, 1) as actions from results where user_id = $userId and game = '$gameName' and difficulty = $i and array_upper(action_times, 1) > 0 order by actions desc limit 1";
//                        else if ($gameName == "pop_pop")
//                        {
//                            $columnName = $i == 0 ? "easy_top" : $i == 1 ? "medium_top" : "hard_top";
//                            $sql = "select $columnName from users where id = $userId";
//			}
                        else
                            $sql = "select end_time - start_time as time from results where user_id = $userId and game = '$gameName' and difficulty = $i and win = true order by start_time - end_time desc limit 1";
                            //$sql = "select win from results where user_id = $userId and game = '$gameName' and difficulty = $i and win = true limit 1";

                        $topResults[$gameName][$i] = $this->db->fetchValue($sql);
                    }
                }
                $topResults["pop_pop"] = $this->db->sqlToArray("select easy_top, medium_top, hard_top from users where id = $userId");
                $result["top_results"] = $topResults;
            }
            else
            {
                $result["result"] = 0;
                $result["msg"] = "passwords did not match";
            }
        }
        else
        {
            $result["result"] = 0;
            $result["msg"] = "no user exists with that username";
        }

        return json_encode($result);
    }

    function SaveResultData()
    {
	// game has complete, store result data against user
        $user_id = $this->getCleanValueFromArguments("user_id");
	$game = $this->getCleanValueFromArguments("game");
        $win = $this->getCleanValueFromArguments("win");
        $record = $this->getCleanValueFromArguments("record");
        $difficulty = $this->getCleanValueFromArguments("difficulty");
        if (!$difficulty) // first version won't have difficulty settings
            $difficulty = 0;
        $min_angle = $this->getCleanValueFromArguments("min_angle");
        $max_angle = $this->getCleanValueFromArguments("max_angle");
        $start_time = $this->getCleanValueFromArguments("start_time");
        $end_time = $this->getCleanValueFromArguments("end_time");
        $action_times = $this->getCleanValueFromArguments("action_times");
        $input_frequencies = $this->getCleanValueFromArguments("input_frequencies");
        $input_frequency_maximums = $this->getCleanValueFromArguments("input_frequency_maximums");

        $sql = "insert into results (user_id, game, win, record, difficulty, min_angle, max_angle, start_time, end_time, action_times, input_frequencies, input_frequency_maximums, created_at, modified_at) values ($user_id, '$game', '$win', '$record', $difficulty, $min_angle, $max_angle, $start_time, $end_time, '{{$action_times}}', '{{$input_frequencies}}', '{{$input_frequency_maximums}}', 'now()', 'now()')";
        $this->db->exesql($sql);

        $result["result"] = 1;
        $result["msg"] = "added results to db $pg_dbname";
        return json_encode($result);
    }

    function GetResultData()
    {
        $user_id = $this->getCleanValueFromArguments("user_id");
        $username = $this->getCleanValueFromArguments("username");
        $game = $this->getCleanValueFromArguments("game");
        $limit = $this->getCleanValueFromArguments("limit");
        $offset = $this->getCleanValueFromArguments("offset");

        $arr["game"] = $game;

        if ($username != "")
        {
             $arr["username_searched"] = $username;
             $id_for_username = $this->db->fetchValue("select id from users where username = '$username'");
             if ($id_for_username)
             {
                 $user_id = $id_for_username;
             }
             else
             {
                 $arr["result"] = 0;
                 $arr["msg"] = "user with username $username does not exist!";
                 return json_encode($arr);
             }
        }

        if (isset($this->arguments["versionNum"]))
        {
            // get the top 3 results
            if ($game == "basketball")
                $sql = "select *, array_upper(action_times, 1) as actions from results where user_id = $user_id and game = '$game' and array_upper(action_times, 1) > 0 order by actions desc limit 3";
            else if ($game == "hockey")
                $sql = "select *, end_time - start_time as time from results where user_id = $user_id and game = '$game' and win = true order by start_time - end_time desc limit 3";
            else if ($game == "pop_pop")
                $sql = "select * from results where user_id = $user_id and game = '$game' and record = true order by created_at desc limit 3";

            $topResults = $this->db->sqlToArray($sql);
            if ($topResults)
                $arr["topResults"] = $topResults;

            // get the most recent 3 results
            $sql = "select * from results where user_id = $user_id and game = '$game' order by created_at desc limit 3";
            $recentResults = $this->db->sqlToArray($sql);
            if ($recentResults)
                $arr["recentResults"] = $recentResults;
            
//            if ($game == "basketball")
//            {
                $sql = "select * from results where user_id = $user_id and game = '$game' and record = true";
                $recordResults = $this->db->sqlToArray($sql);
                if ($recordResults)// && count($recordResults) > 3)
                    $arr["recordResults"] = $recordResults;
//            }
        }
        else
        {
            if ($limit == -1)
                $sql = "select * from results where user_id = $user_id and game = '$game'";
            else
                $sql = "select * from results where user_id = $user_id and game = '$game' limit $limit offset $offset";

            $results = $this->db->sqlToArray($sql);

            if ($results)
                $arr["found_results"] = $results;
        }

        $arr["result"] = 1;
        return json_encode($arr);
    }

    function SetHighLevel()
    {
        $user_id = $this->getCleanValueFromArguments("user_id");
        $difficultyColumnName = $this->getCleanValueFromArguments("difficultyColumnName");
        $highLevel = $this->getCleanValueFromArguments("highLevel");

        $queryResult = $this->db->exesql("update users set $difficultyColumnName = $highLevel where id = $user_id");
        if (pg_affected_rows($queryResult) > 0)
            $arr["result"] = 1;
        else
            $arr["result"] = 0;

        return json_encode($arr);
    }


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    function DailyProcess()
    {
//        $log = new Logger('api');
//        $log->pushHandler(new StreamHandler('/var/log/picto/rhys.log', Logger::INFO));

        // get any fresh competition entries and notify teachers
        $sql = "select a.id, a.competition_id, a.design_id, a.description, b.\"DisplayName\", b.\"ThumbnailUrl\", c.\"UserName\", c.\"UnlockCode\", d.email_subject from competition_submissions a, \"Design\" b, \"User\" c, competitions d where a.notified = 'false' and b.\"DesignUID\" = a.design_id and c.\"UserUID\" = b.\"OwnerUID\" and d.id = a.competition_id";
        $newSubmissions = $this->db->sqlToArray($sql);

        // get list of unlock codes
        $unlockCodes = array();
        for ($i = 0; $i < count($newSubmissions); $i++)
        {
            $unlockCode = $newSubmissions[$i]["UnlockCode"];
            if (!in_array($unlockCode, $unlockCodes))
                array_push($unlockCodes, $unlockCode);
        }

        // if we have any schools to notify...
        if (count($unlockCodes) > 0)
        {
            // get teacher emails for each code and send data
            foreach ($unlockCodes as $unlockCode)
            {
                // let's first set the common data for the email
                $schoolSubmissions = array();

                $designIds = "";
                foreach ($newSubmissions as $newSubmission)
                {
                    if ($newSubmission["UnlockCode"] == $unlockCode)
                    {
                        array_push($schoolSubmissions, $newSubmission);
                        $designIds = $designIds . $newSubmission["design_id"] . ", ";
                    }
                }

                $global_merge_vars = array(
                    array('name' => 'DESIGNS', 'content' => $schoolSubmissions)
                );

                // get the emails for this unlock code
                $sql = "select a.email from teachers a, teachers_unlock_codes_joins b where a.id = b.teacher_id and b.unlock_code_id = $unlockCode";
                $teacherEmails = $this->db->sqlToArray($sql);

                if ($teacherEmails)
                {
                    // and send out the emails one per teacher
                    foreach ($teacherEmails as $email)
                    {
                        $to = $email["email"];
                        $this->SendEmailMandrill("dailysummary", $global_merge_vars, $email, "Student competition activity", $this->support_email_address, $this->application_name, "true");

                        $sql = "insert into web_logs (log_type, log_level, message, created_at) values (1, 3, 'daily summary - trying to email : $to', localtimestamp)";
                        $this->db->exesql($sql);

                        $designCount = count($schoolSubmissions);
                        //$log->addInfo("sending $designCount designs ($designIds) to $to... unlock code is $unlockCode");
                    }
                }

                // send the same email to our support address
                $this->SendEmailMandrill("dailysummary", $global_merge_vars, $this->support_email_address, "Student competition activity - license code : $unlockCode", $this->support_email_address, $this->application_name, "true");
            }
        }

        // before we leave, mark all found designs as 'notified'
        foreach ($newSubmissions as $newSubmission)
        {
            $submissionId = $newSubmission["id"];
            $sql = "update competition_submissions set notified = 'true' where id = $submissionId";
            $this->db->exesql($sql);
        }
    }

    function AddAllToRenderQueue()
    {
        //$sql = "select \"DesignUID\" from \"Design\"";
        //$sql = "select \"DesignUID\" from \"Design\" where \"Type\" = '3'";
        //$sql = "select \"DesignUID\" from \"Design\" where \"DesignUID\" not in (select \"DesignUID\" from \"DesignsToRender\") order by \"ModificationDate\" desc limit 4000 offset 0";
        $sql = "select \"DesignUID\" from \"Design\" where \"OwnerUID\" in (select \"UserUID\" from \"User\" where \"UnlockCode\" in (select codeuid from \"UnlockCodes\" where \"Code\" ilike '85%')) and \"DesignUID\" not in (select \"DesignUID\" from \"DesignsToRender\") order by \"ModificationDate\" desc limit 4000 offset 0";
        //$sql = "select \"DesignUID\" from \"Design\" order by \"ViewCount\" desc limit 3000 offset 1000";
        //$sql = "select \"DesignUID\" from \"Design\" where \"OwnerUID\" in (select \"UserUID\" from \"User\" where \"UserName\" ilike 'RolandTest%')";
        //$sql = "select \"DesignUID\" from \"Design\" where \"DesignUID\" in ('9478e3cb-7e39-461b-9d48-ca7fd54f9564','3ea99ff5-6fca-40c4-88e7-483f46d946ed','1fe25a1a-25b4-47d2-bc32-62c3895e7c17')";
        //$sql = "select \"DesignUID\" from \"Design\" where \"ModificationDate\" > '2015-05-01' and \"Type\" = 3 order by \"ModificationDate\" desc";
        //$sql = "select \"DesignUID\" from \"Design\" where \"DesignUID\" in (select \"DesignUID\" from \"DesignTag\" where \"TagText\" = '_upvoted')";



        $designs = $this->db->sqlToArray($sql);

        if ($designs)
        {
            for ($i=0; $i < count($designs); $i++)
            {
                echo 'Inserting design '.$designs[$i]['DesignUID'];
                $this->InsertDesignIntoRenderQueue($designs[$i]['DesignUID'], 0, 't', 'f', 'f');
            }
        }
    }

    function AddAllToExportQueue()
    {
        //$sql = "select \"DesignUID\" from \"Design\"";
        //$sql = "select \"DesignUID\" from \"Design\" where \"OwnerUID\" = 575";
        //$sql = "select \"DesignUID\" from \"Design\" where \"Type\" = 9";
        //$sql = "select \"DesignUID\" from \"Design\" where \"DesignUID\" = '73bb0e1e-ad8c-4a9a-9593-7d166a5867d0'";
        //$sql = "select \"DesignUID\" from \"Design\" order by \"ModificationDate\" desc limit 30 offset 0";
        $sql = "select \"DesignUID\" from \"Design\" where \"ModificationDate\" > '2015-05-01'";


        $designs = $this->db->sqlToArray($sql);

        if ($designs)
        {
            for ($i=0; $i < count($designs); $i++)
            {
                $designUID = $designs[$i]['DesignUID'];
                echo 'Inserting design '.$designUID.' ';

                $this->InsertDesignIntoExportQueue($designUID);

                $this->db->exesql("update \"DesignsToExport\" set \"ProcessingTimeLimit\" = '2014-01-01' where \"DesignUID\" = '$designUID'");
            }
            echo "\r\n";
        }
    }

    private function ContainsBadWord($text, $msg, $sql_to_run)
    {
        $sql = "select regex from bad_words where language = 'en' and '$text' ~* regex limit 1";
        $queryResult = $this->db->fetchValue($sql);

        if ($queryResult)
        {
            $last_id = "";
            if ($sql_to_run != "")
            {
                // add this to the bad_word_captures table so we can approve/reject
                $sql = "insert into bad_word_captures (sql_to_run, created_at) values ('$sql_to_run', localtimestamp)";
                $this->db->exesql($sql);
                $last_id = $this->db->fetchValue("select lastval()");
            }

            if ($msg != "")
            {
            $globalMergeVars = array(
                array('name' => 'BLOCKEDTEXT', 'content' => $text),
                array('name' => 'REGEX', 'content' => $queryResult),
                array('name' => 'SERVERMSG', 'content' => $msg),
                array('name' => 'CHOICE', 'content' => $sql_to_run == "" ? 'false' : 'true'),
                array('name' => 'ID', 'content' => $last_id),
            );
            $this->SendEmailMandrill("badworddetected", $globalMergeVars, $this->info_email_address, "Bad word detected!", $this->info_email_address, $this->application_name, "false");
            }

            //$log = new Logger('api');
            //$log->pushHandler(new StreamHandler('/var/log/picto/api.log', Logger::INFO));
            //$log->addInfo("Detected a bad word in the text '$text' matching the regex '$queryResult'");
            return $queryResult;
        }
        else
            return False;
    }

    protected function SendCurlPost($url, $postdata, $header, $keyFile = '', $certFile = '')
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $postdata);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        curl_setopt($curl, CURLOPT_HEADER, 1);
    
        // for azure cert
        if ($keyFile)
        {
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
            curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($curl, CURLOPT_SSLKEY, $keyFile);
            curl_setopt($curl, CURLOPT_SSLCERT, $certFile);
        }

        $response = curl_exec($curl);
        $this->response_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

        $header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
        $response_header = substr($response, 0, $header_size);
        $response_body = substr($response, $header_size);

        if ($this->response_code != 200 && $this->response_code != 202)
        {
            curl_close($curl);

            //die('header: '.$response_header . ' body: ' . $response_body);
            error_log('curl failed - url ' . $url . ' header: '.$response_header . ' body: ' . $response_body);
        }
        else if ($response_body == "")
        {
            $response_body = 'success';
        }
        

        //var_dump($this->url);
        // Uncomment next four lines to see/debug full cURL response
        // $curl_info = curl_getinfo($curl);
        // var_dump($curl_info);
        // var_dump($response_header);
        // var_dump($response_body);

        curl_close($curl);

        return $response_body;
    }

    function RebootGeneratorServerRackspace($rackspace_id, $reboot_type = 'SOFT')
    {
        // check whether rackspace api access token has expired
        date_default_timezone_set("UTC");
        $now = new DateTime;
        $nowStr = $now->format('Y-m-d H:i:s');

        $token_expiry = $this->db->fetchValue("select token_expiry from rackspace");
        $token_expiry_date = new DateTime($token_expiry);
        if ($token_expiry_date < $now)
        {
            var_dump($token_expiry_date);

            // get new access token data
            $api_key = $this->db->fetchValue("select api_key from rackspace");

            $post_params = array(
                'auth' => array(
                    'RAX-KSKEY:apiKeyCredentials'  => array(
                        'username'  => 'peoplepilot',
                        'apiKey' => $api_key,
                    ),
                ),
            );

            $header = array('Content-Type: application/json',);

            $response_data = $this->SendCurlPost("https://identity.api.rackspacecloud.com/v2.0/tokens", json_encode($post_params), $header);


            $token = "";
            $expiry = "";
            if ($response_data)
            {
                $tokenData = json_decode($response_data);
                if ($tokenData)
                {
                    $token = $tokenData->access->token->id;
                    $token_expiry = $tokenData->access->token->expires;
                }
            }

            if ($token == "" || $token_expiry == "")
                die($this->JsonError("rackspace token fail"));

            $sql = "update rackspace set token='$token', token_expiry='$token_expiry'";
            $this->db->exesql($sql);
        }
        else
        {
            // get existing info
            $token = $this->db->fetchValue("select token from rackspace");
        }

        // reboot server
        if ($token)
        {
            $url = "https://dfw.servers.api.rackspacecloud.com/v2/682709/servers/" . $rackspace_id . "/action";

            $post_params = array(
                'reboot' => array(
                    'type'  => $reboot_type,
                ),
            );

            $header = array('Content-Type: application/json', 'Accept: application/json', 'X-Auth-Project-Id: 682709', "X-Auth-Token: $token");

            $response_data = $this->SendCurlPost($url, json_encode($post_params), $header);

            $this->db->exesql("update generator_servers set message='' where rackspace_id = '$rackspace_id'");

            $test = 'test';
            var_dump($test);
            var_dump($response_data);

            if ($response_data)
                return TRUE;

        }

        return FALSE;
    }


    function RebootGeneratorServerAzure($server_name)
    {
        $header = array('Content-Type: text/xml','x-ms-version: 2015-04-01');
        $post_data = '<RestartRoleOperation xmlns="http://schemas.microsoft.com/windowsazure" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><OperationType>RestartRoleOperation</OperationType></RestartRoleOperation>';
        $response_data = $this->SendCurlPost("https://management.core.windows.net/2039be25-3c5f-4a46-aed0-f25e481ac904/services/hostedservices/$server_name/deployments/$server_name/roleinstances/$server_name/Operations", $post_data, $header, '/etc/httpd/azure/rsakey.pem', '/etc/httpd/azure/client.pem');

        // reboot server
        if ($response_data)
            return TRUE;

        return FALSE;
    }


    function ClearImagesFromDeletedDesigns()
    {
        $dir = new DirectoryIterator("/var/www/html/picto/img/design");

        $deletecount = 0;
        foreach ($dir as $fileinfo) {
            if (!$fileinfo->isDot()) {

                $pathname = $fileinfo->getPathname();
                $filename = pathinfo($pathname, PATHINFO_FILENAME);

                $sql = "select count(*) from \"Design\" where \"DesignUID\"='$filename'";
                $designcount = $this->db->fetchValue($sql);

                if ($designcount == 0)
                {
                    echo 'delete '.$filename."\r\n";
                    unlink($pathname);
                    $thumbname = '/var/www/html/picto/img/design/thumbnail/'.$filename.'.jpg';
                    if (file_exists($thumbname))
                        unlink($thumbname);

                    $thumbname = '/var/www/html/picto/img/design/thumbnail/'.$filename.'-190x190.jpg';
                    if (file_exists($thumbname))
                        unlink($thumbname);

                    $deletecount = $deletecount + 1;
                }
                else
                    echo 'keep '.$filename."\r\n";
            }

//            if ($deletecount > 5)
//                break;
        }

        echo 'deleted ' . $deletecount . "images \r\n";
    }

    function ClearStlsFromDeletedDesigns()
    {
        $dir = new DirectoryIterator("/var/www/html/picto/stl");

        $deletecount = 0;
        foreach ($dir as $fileinfo) {
            if (!$fileinfo->isDot()) {

                $subdir = new DirectoryIterator($fileinfo->getPathname());

                foreach ($subdir as $subFileInfo)
                {
                    if (!$subFileInfo->isDot())
                    {
                        $pathname = $subFileInfo->getPathname();
                        $filename = pathinfo($pathname, PATHINFO_FILENAME);
                    
                        $sql = "select count(*) from \"Design\" where \"DesignUID\"='$filename'";
                        $designcount = $this->db->fetchValue($sql);

                        if ($designcount == 0)
                        {
                            if (is_file($pathname))
                            {
                                echo 'delete '.$pathname."\r\n";
                                unlink($pathname);
                            }
                            else
                            {
                                echo 'delete dir '.$pathname."\r\n";
                                system("rm -rf ".escapeshellarg($pathname));
                            }

                            $deletecount = $deletecount + 1;
                        }
                        else
                            echo 'keep '.$pathname."\r\n";
                    }
                }
            }

//            if ($deletecount > 5)
//                break;
        }

        echo 'deleted ' . $deletecount . " stls \r\n";

    }
 
    function CheckImageCreatorIdleTime()
    {
        $sql = "select * from generator_servers";
        $servers = $this->db->sqlToArray($sql);

        date_default_timezone_set("UTC");
        $now = new DateTime;
        $nowStr = $now->format('Y-m-d H:i:s');

        if ($servers)
        {
            for ($i=0; $i < count($servers); $i++)
            {
                // check if server has made a request within the specified time
                $serverType = $servers[$i]['type'];
                if ($serverType == 'image')
                    $maxIdle = new DateInterval("PT10M");
                else
                    $maxIdle = new DateInterval("PT20M");

                $last_request = new DateTime($servers[$i]['last_request']);
                $last_reboot = new DateTime($servers[$i]['last_reboot']);
                if ($last_request > $last_reboot)
                    $last_request_plus_max_idle = clone $last_request;
                else
                    $last_request_plus_max_idle = clone $last_reboot;

                $last_request_plus_max_idle->add($maxIdle);

                $rackspace_id = $servers[$i]['rackspace_id'];
                $server_name = $servers[$i]['name'];

//                error_log('before reboot section for ' . $server_name . ' now ' . $now->format('Y-m-d H:i:s') . ' last ' . $servers[$i]['last_request'] . ' last reboot ' . $servers[$i]['last_reboot']);
 

                if ($now > $last_request_plus_max_idle && $servers[$i]['reboot_inactive'] == 't' && $servers[$i]['status'] != 'rebooting')
                {
//                    error_log('reboot section for ' . $servers[$i]['name']);

                    // reboot server and send notification email
                    if ($servers[$i]['host'] == 'rackspace')
                        $reboot_success = $this->RebootGeneratorServerRackspace($rackspace_id);
                    else
                        $reboot_success = $this->RebootGeneratorServerAzure($server_name);

                    if ($reboot_success)
                    {
                        $subject = $servers[$i]['name'] . " server rebooted";
                        $this->db->exesql("update generator_servers set status='rebooting' where name = '$server_name'");
                        $this->db->exesql("update generator_servers set max_request_interval=0 where name = '$server_name'");
                        $this->db->exesql("update generator_servers set last_reboot='$nowStr' where name = '$server_name'");
                    }
                    else
                    {
                        $subject = $servers[$i]['name'] . " server reboot failed";
                        $this->db->exesql("update generator_servers set status='reboot failed' where name = '$server_name'");
                    }

                    $message = "Didn't send any requests for the past " . ($now->diff($last_request)->format('%i minutes')) . ". Designs ".$servers[$i]['last_designs'] . '<br/><img src="http://3d.makersempire.com/img/design/'.$servers[$i]['last_designs'].'.jpg">';
                    $this->SendEmailSendGrid($this->debug_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');
                }


                // check if server dead
                $last_request_plus_max_idle->add($maxIdle);
                $last_request_plus_max_idle->add($maxIdle);
                if ($now > $last_request_plus_max_idle && $servers[$i]['reboot_inactive'] == 't' && $servers[$i]['status'] != 'dead')
                {
                    error_log('rebooting hard');

                    if ($servers[$i]['host'] == 'rackspace')
                        $reboot_success = $this->RebootGeneratorServerRackspace($rackspace_id, 'HARD');
                    else
                        $reboot_success = $this->RebootGeneratorServerAzure($server_name);

                    if ($reboot_success)
                    {
                        $subject = $servers[$i]['name'] . " server rebooted AGAIN";
                        $this->db->exesql("update generator_servers set status='dead' where name = '$server_name'");
                        $this->db->exesql("update generator_servers set max_request_interval=0 where name = '$server_name'");
                        $this->db->exesql("update generator_servers set last_reboot='$nowStr' where name = '$server_name'");
                    }
                    else
                    {
                        $subject = $servers[$i]['name'] . " server reboot failed AGAIN";
                        $this->db->exesql("update generator_servers set status='dead' where name = '$server_name'");
                        $this->db->exesql("update generator_servers set status='reboot failed' where name = '$server_name'");
                    }

                    $message = "Didn't send any requests for the past " . ($now->diff($last_request)->format('%i minutes')) . " minutes.";
                    $this->SendEmailSendGrid($this->debug_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');
                }
            }
        }
    }

    function API($_arguments)
    {
        $this->arguments = $_arguments;

        $this->db = new pgConnect();
        if(isset($db->failMessage))
        {
            die($this->JsonError($db->failMessage));
        }

        if (array_key_exists('method', $this->arguments) == false || trim($this->arguments['method'])=='')
        {
            die($this->JsonError('you have to let us know which method you want to call'));
        }

        if (!in_array($this->arguments['method'], $this->getValidMethodList()))
        {
            die($this->JsonError('the method '.$this->arguments['method']. ' is not valid'));
        }
    }

    private function checkUser($checkToken=false, $onlyForTeachers=false)
    {
        $useUsername = isset($this->arguments["username"]);

        if (!$useUsername)
        {
            if($checkToken)
            {
                $sql = "select \"SessionToken\", \"UserUID\" from \"User\" where lower(\"Email\")='?email?'";
            }
            else
            {
                $sql = "select \"Password\", \"UserUID\" from \"User\" where lower(\"Email\")='?email?'";
            }
            $email = strtolower($this->getCleanValueFromArguments("email", true));
            $sql = str_replace("?email?", $email, $sql);
        }
        else
        {
            if($checkToken)
            {
                $sql = "select \"SessionToken\", \"UserUID\" from \"User\" where lower(\"UserName\")='?username?'";
            }
            else
            {
                $sql = "select \"Password\", \"UserUID\" from \"User\" where lower(\"UserName\")='?username?'";
            }
            $username = strtolower($this->getCleanValueFromArguments("username", true));
            $sql = str_replace("?username?", $username, $sql);
        }

        $result = $this->db->fetchArray($sql);
        if (!$result)
        {
            die($this->JsonError('User cannot be found.', 'ServerMessage1'));
        }

        // special access for web server
        if (($_SERVER['REMOTE_ADDR'] == '191.236.98.142' || $_SERVER['REMOTE_ADDR'] == '203.122.234.87') && $this->getCleanValueFromArguments("token", true) == 'H3ll0')
        {
            error_log("Allowed special access");
        }
        else
        {
            if ($onlyForTeachers)
                die($this->JsonError('You have no permission to do this. Only teachers allowed.', 'ServerMessage2'));

            $entryToTest = $checkToken ? $result['SessionToken'] : $result['Password'];
            if (!$entryToTest)
            {
                if (!$useUsername)
                    die($this->JsonError('Your email address was not foud in the database.', 'ServerMessage3'));
                else
                    die($this->JsonError('Your username was not foud in the database.', 'ServerMessage4'));
            }
            else
            {
                $token = $this->getCleanValueFromArguments("token", true);
                $expectedHash = $this->getCleanValueFromArguments("password", true);
                $hash = md5($token.$entryToTest);

            //    error_log('token '. $token);
            //    error_log('expected ' . $expectedHash);
            //    error_log('hash '. $hash);

                if ($hash !== $expectedHash)
                {
                    if($checkToken)
                    {
                        $result["result"]=-1;
                        $result["msg"]='Token incorrect.';
                        $result["msgKey"] = 'ServerMessage52';
                        die(json_encode($result));
                    }
                    else
                    {
#                    die($this->JsonError('Password incorrect.<br/>Click <a href="'.WEBROOT.'/sign_up/forgotpass.php">here</a> if you have forgotten your password.'));
                        die($this->JsonError('Password incorrect.', 'ServerMessage5'));
                    }
                }
            }
        }

        $id = $result['UserUID'];
        if (!$id)
        {
#            $sql = "select \"UserUID\" from \"User\" where \"Email\"='?email?'";
#            $sql = str_replace("?email?", $this->getCleanValueFromArguments("email", true), $sql);
#            $id = $this->db->fetchValue($sql);

#            if (!$id)
#            {
#                die($this->JsonError('Email address incorrect', 'ServerMessage6'));
#            }
#            else
#            {
#                die($this->JsonError('Email address or password incorrect.<br/>Click <a href="'.WEBROOT.'/sign_up/forgotpass.php">here</a> if you have forgotton your password.'));
                if (!$useUsername)
                    die($this->JsonError('Email address or password incorrect.', 'ServerMessage7'));
                else
                    die($this->JsonError('Username or password incorrect.', 'ServerMessage8'));
#            }

        }
        else
        {
            $activated = $this->db->fetchValue('select "AccountActivated" from "User" where "UserUID"='."$id");
            if ($activated != 't')
            {
#                die($this->JsonError('You have not yet activated your account.<br/>Please check your email for activation instructions.<br/>Click <a href="'.WEBROOT.'/sign_up/resendactivation.php?email='.$email.'">here</a> to resend the email.'));
                die($this->JsonError('You have not yet activated your account.', 'ServerMessage9'));
            }
        }

        $this->currentUserId = $id;
        return $id;
    }

    public function getMethod()
    {
        return $this->arguments['method'];
    }

    private function getCleanValueFromArguments($param, $required=false)
    {
        if ($required && !isset($this->arguments[$param]))
        {
            die($this->JsonError("$param is required and not set"));
        }
        else if (!isset($this->arguments[$param]))
        {
            return pg_escape_string('');
        }
        else
        {
            return pg_escape_string($this->arguments[$param]);
        }
    }

    private function JsonError($errorMessage, $errorMessageKey = '')
    {
        $result["result"]=0;
        $result["msg"]=$errorMessage;
        if ($errorMessageKey != '')
            $result["msgKey"]=$errorMessageKey;
        return json_encode($result);
    }

    function GUID()
    {
        if (function_exists('com_create_guid') === true)
        {
            return trim(com_create_guid(), '{}');
        }

        return sprintf('%04X%04X-%04X-%04X-%04X-%04X%04X%04X', mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(16384, 20479), mt_rand(32768, 49151), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535));
    }


//    function AddUser()
//    {
//        $arr["UserName"] = $this->getCleanValueFromArguments('username', true);
//        $arr["Password"] = $this->getCleanValueFromArguments('password', true);
//        $arr["DisplayName"] = $this->getCleanValueFromArguments('UserDisplayName', true);
//        $arr["Description"] = $this->getCleanValueFromArguments('UserDescription');
//        $arr["Email"] = $this->getCleanValueFromArguments('UserEmail', true);
//        $arr["PhoneNumber"] = $this->getCleanValueFromArguments('UserPhoneNumber');
//        $arr["LinkWeb"] = $this->getCleanValueFromArguments('UserLinkWeb');
//        $arr["Location"] = $this->getCleanValueFromArguments('UserLocation');

//        date_default_timezone_set("UTC");
//        $arr["AccountCreationDate"] =  date("Y-m-d H:i:s", time());

//        return $this->db->InsertAndReturnNewId("User", $arr);
//    }

    private function CreateUser($email, $username, $password)
    {
        $arr["Email"] = $email;
        $arr["UserName"] = $username;
        $arr["Password"] = $password;
        $arr["DisplayName"] = $this->getCleanValueFromArguments('displayname');
        $arr["Description"] = $this->getCleanValueFromArguments('UserDescription');
        //$arr["PhoneNumber"] = $this->getCleanValueFromArguments('UserPhoneNumber');
        //$arr["LinkWeb"] = $this->getCleanValueFromArguments('UserLinkWeb');
        //$arr["LinkFacebook"] = $this->getCleanValueFromArguments('UserLinkFacebook');
        //$arr["TwitterName"] = $this->getCleanValueFromArguments('UserTwitterName');
        //$arr["Location"] = $this->getCleanValueFromArguments('UserLocation');
        $arr["AccountCreationID"] = "ME";
        $arr["AccountCreationDate"] = date("Y-m-d H:i:s", time());
        $arr["app_version_string"] = $this->getCleanValueFromArguments('version');
        $arr["device_type"] = $this->getCleanValueFromArguments('deviceType');
        $arr["device_model"] = $this->getCleanValueFromArguments('deviceModel');
        $arr["device_os"] = $this->getCleanValueFromArguments('deviceOS');

        $badWordRegex = $this->ContainsBadWord($username, "", "");
        if ($badWordRegex)
            $arr["username_approved"] = "false";

        # send email to user asking them to activate their account
        $token = md5(time());
        $arr["AccountToken"] = $token;
        //$arr["AccountActivated"] = '0'; // note: restore this if you want to force the user to activate the account by clicking link in email
        $arr["AccountActivated"] = 't';

        # create session token in case we are creating account via app
        $sessionToken = md5(mt_rand());
        $arr["SessionToken"] = $sessionToken;
            
        $new_id = $this->db->InsertAndReturnNewId("User", $arr);

        //  note: restore this if you want to force the user to activate the account by clicking link in email
        //    $this->SendActivationEmail();
        //    return json_encode($arr);
        $this->SetUserDefaultSettings($new_id); // note: this was added after removing activation requirement
            

        // if there was a bad word in this username, send allow/reject email
        if ($badWordRegex)
            $this->ContainsBadWord($username, "user has created an account with this username. it will be invisible to other users unless approved", "update \"User\" set username_approved = ''true'' where \"UserUID\" = ''$new_id''");

        // send notification
        // $subject = "New account was created";
        // $message = "User name: " . $username . "<br/>User ID: " . $new_id;
        // if ($email != '')
        // {
        //     $message = $message . "<br/>User email: " . $email;
        //     $this->SendActivationEmail();
        // };
        // $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');
            

        $foundCompetitionResult = $this->GetValidCompetitionArray("en-GB", "2.7", $new_id);
        if ($foundCompetitionResult)
            $result["ValidCompetition"] = $foundCompetitionResult;

        $result["UserUID"] = $new_id;
        $result["UserName"] = $username;
        $result["SessionToken"] = $sessionToken;
        $result["result"] = 1;
            
        return json_encode($result);
    }

    function CreateAccount()
    {
        $email = strtolower($this->getCleanValueFromArguments("email", true));
        if ($email == '')
        {
            die($this->JsonError("Email cannot be empty", 'ServerMessage11'));
        }

        $username = $this->getCleanValueFromArguments('displayname');
        if ($username == '')
        {
            die($this->JsonError("Username cannot be empty", 'ServerMessage12'));
        }

        // see if user exists already in the social db
        $sql = "select \"UserUID\" from \"User\" where lower(\"Email\")='?email?'";
        $sql = str_replace("?email?", $email, $sql);

        $id = $this->db->fetchValue($sql);
        $this->currentUserId = $id;

        if (!$this->currentUserId)
        {
            # need to add user to social db
            $password = md5($this->getCleanValueFromArguments('password', true));

            return $this->CreateUser($email, $username, $password);
        }
        else
        {
            die($this->JsonError("Account already exists for this email address", 'ServerMessage13'));
        }
    }

    function CreateAccountWithUsername()
    {
        $username = $this->getCleanValueFromArguments('username', true);
        if ($username == '')
        {
            die($this->JsonError("Username cannot be empty", 'ServerMessage12'));
        }

        // see if user exists already in the social db
        $sql = "select \"UserUID\" from \"User\" where lower(\"UserName\")='?username?'";
        $lower_username = strtolower($username);
        $sql = str_replace("?username?", $lower_username, $sql);

        $id = $this->db->fetchValue($sql);
        $this->currentUserId = $id;

        if (!$this->currentUserId)
        {
            # need to add user to social db
            $password = md5($this->getCleanValueFromArguments('password', true));

            return $this->CreateUser('', $username, $password);
        }
        else
        {
            die($this->JsonError("Account with selected username already exists in the database", 'ServerMessage14'));
        }
    }

    function LoginOrCreateUserWithUsername()
    {
        $username = $this->getCleanValueFromArguments("username", true);

        if (strlen($username) > 1)
        {
            $sql = "select count(\"UserName\") from \"User\" where lower(\"UserName\")='?username?'";
            $lower_username = strtolower($username);
            $sql = str_replace("?username?", $lower_username, $sql);
            $count = $this->db->fetchValue($sql);
            $result["isNew"] = $count == 0 ? 't' : 'f';

            if ($count == 0)
            {
                $this->CreateAccountWithUsername();
            }
            $count = $this->db->fetchValue($sql);
            if ($count == 0)
            {
                $result["msg"] = "Unknown error has occurred while creating a new user";
                $result["msgKey"] = 'ServerMessage53';
                $result["result"] = 0;

                return json_encode($result);
            }
            else
            {
                $password = md5($this->getCleanValueFromArguments('password', true));
                $sql = "select count(*) from \"User\" where \"UserName\"='$username' and \"Password\"='$password'";
                $count = $this->db->fetchValue($sql);
                if ($count > 0)
                {
                    $this->arguments['password'] = $this->arguments['passwordToLogin'];
                    return $this->LoginUser($result["isNew"] == 't');
                }
                else
                {
                    $result["msg"] = "Password incorrect.";
                    $result["msgKey"] = 'ServerMessage5';
                    $result["result"] = 0;

                    $exampleUsernames = array();
                    for ($i=0; $i < 3; $i++)
                    {
                        $isUsernameOk = false;
                        $newUsername = '';
                        while (!$isUsernameOk)
                        {
                            $newUsername = $username . mt_rand(0, 99999);
                            $sql = "select count(\"UserName\") from \"User\" where \"UserName\"='$newUsername'";
                            $count = $this->db->fetchValue($sql);
                            if ($count == 0)
                            {
                                $isUsernameOk = true;
                            }
                        }
                        $exampleUsernames[] = $newUsername;
                    }
                    $result["exampleUsernames"] = implode(',', $exampleUsernames);
                }
            }
        }
        else
        {
            die($this->JsonError("Username cannot be empty", 'ServerMessage12'));
        }

        return json_encode($result);
    }

    public function SendEmailSendGrid($to, $subject, $body, $from, $fromName, $attachment = "")
    {
        $sendgrid = new SendGrid('makersempire', 'SGM33d!');
        $mail = new SendGrid\Email();
        $mail->
          addTo($to)->
          setFrom($from)->
          setFromName($fromName)->
          setSubject($subject)->
          setHtml($body);
        if ($attachment != "")
            $mail->addAttachment($attachment);

        return $sendgrid->
            send($mail);
    }

    public function SendEmailMandrill($templateName, $globalVarArray, $to, $subject, $from, $fromName, $useHandlebars, $attachment = null)
    {
        $mandrill = new Mandrill('1Wd3fvVQNJnJNmbqk-iSYw');

	$templateContent = array();

	$message = array(
	    'subject' => $subject,
	    'from_email' => $from,
            'from_name' => $fromName,
            'to' => array(
                array(
                    'email' => $to
               )
            ),
            'merge_language' => $useHandlebars == "true" ? "handlebars" : "mailchimp",
            'global_merge_vars' => $globalVarArray,
            'attachments' => (isSet($attachment) ? $attachment : array())
	);

	$result = $mandrill->messages->sendTemplate($templateName, $templateContent, $message);
    }

    function SendActivationEmail()
    {
        $email = strtolower($this->getCleanValueFromArguments('email', true));

        # find account matching email
        $sql = "select count(\"UserUID\") from \"User\" where lower(\"Email\")='$email'";

        $count = $this->db->fetchValue($sql);

        if ($count!=1)
        {
            return $this->JsonError("Your email is not valid", 'ServerMessage15');
        }

        $token = $this->db->fetchValue("select \"AccountToken\" from \"User\" where lower(\"Email\")='$email'");
        $displayName = $this->db->fetchValue("select \"UserName\" from \"User\" where lower(\"Email\")='$email'");

        if (!$token)
        {
            return $this->JsonError("A token error occurred.", 'ServerMessage16');
        }

        # send email to user asking them to activate their account
        $url = WEBROOT . "sign_up/activate_account.php?email=$email&token=$token";
        //$body = "<html><body><p>Hello " . $displayName . ",<br/><br/>Welcome to " . $this->application_name . " and thank you for registering.  Please activate your new " . $this->application_name . " account by clicking <a href=\"".$url."\">here</a><br/><br/>We are working hard to make " . $this->application_name . " amazing, so please give it a try and let us know what you think.<br/><br/>To unsubscribe please email " . $this->support_email_address . "<br/><br/>" . $this->application_name . " is a product by:<br/>People Pilot Pty Ltd<br/>Coromandel Valley, Australia<br/></p></body></html>"; // note: restore this to send activation link
        $body = "<html><body><p>Hello " . $displayName . ",<br/><br/>Welcome to " . $this->application_name . " and thank you for registering.<br/><br/>We are working hard to make " . $this->application_name . " amazing, so please give it a try and let us know what you think.<br/><br/>To unsubscribe please email " . $this->support_email_address . "<br/><br/>" . $this->application_name . " is a product by:<br/>Makers Empire Pty Ltd<br/>Email: info@makersempire.com<br/>Phone: +61 403 347 994<br/>Address:<br/>Yungondi Building<br/>North Terrace<br/>Adelaide, Australia<br/></p></body></html>";
        $this->SendEmailSendGrid($email, "Your new " . $this->application_name . " account", $body, $this->support_email_address, $this->application_name . ' Support');
    }
    
    function ActivateAccount()
    {
        $token = $this->getCleanValueFromArguments('token', true);
        $email = strtolower($this->getCleanValueFromArguments('email', true));

        # find account matching email and token
        $sql = "select count(\"UserUID\") from \"User\" where \"AccountToken\"='$token' and lower(\"Email\")='$email'";

        $count = $this->db->fetchValue($sql);

        if ($count != 1)
        {
            return $this->JsonError("Your email or your token is not valid", 'ServerMessage17');
        }

        $sql = "select \"UserUID\" from \"User\" where \"AccountToken\"='$token' and lower(\"Email\")='$email'";

        $user_id = $this->db->fetchValue($sql);

        if (!$user_id)
        {
            return $this->JsonError("Your token expired", 'ServerMessage18');
        }

        # set account activated flag
        $sql = "update \"User\" set \"AccountActivated\"='1', \"AccountToken\"='' where \"UserUID\"='$user_id'";
        $this->db->exesql($sql);

        $this->SetUserDefaultSettings($user_id);
    }

    public function SendForgetPasswordLink()
    {
        $useUsername = isset($this->arguments["username"]);

        if (!$useUsername)
        {
            $email = strtolower($this->getCleanValueFromArguments('email', true));
        }
        else
        {
            $sql = "select \"Email\" from \"User\" where lower(\"UserName\")='?username?'";
            $username = strtolower($this->getCleanValueFromArguments("username", true));
            $sql = str_replace("?username?", $username, $sql);
            $email = $this->db->fetchValue($sql);
            
            if ($email == NULL || $email == '')
            {
                return $this->JsonError("Unfortunately, there is no email address related to this account so we could not send you further instructions", 'ServerMessage19');
            }
        }

        # find account matching email
        if (!useUsername)
        {
            $sql = 'select "UserUID" from "User" where lower("Email")=?email?';
            $sql = str_replace("?email?", "'$email'", $sql);
	}
        else
        {
            $sql = "select \"UserUID\" from \"User\" where lower(\"UserName\")='?username?'";
            $sql = str_replace("?username?", $username, $sql);
	}

        $user_id = $this->db->fetchValue($sql);
        if (!$user_id)
        {
            return $this->JsonError("User cannot be found", 'ServerMessage1');
        }

        $token = md5(time());
        $displayName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\"=$user_id");

        $sql = "update \"User\" set \"ResetPasswordToken\"='$token', \"TokenExpireDate\"= current_date+interval '48 hours' where \"UserUID\"=$user_id";
        $this->db->exesql($sql);

        # send email to user asking them to activate their account
//        $url = WEBROOT . "sign_up/reset_password.php?email=$email&token=$token";
        $url = "https://www.makersempire.com/reset_password?email=$email&token=$token";

        //$body = "<html><body><p>Hello " . $displayName . ",<br/><br/>A request to reset the password for your " . $this->application_name . " account has been received.<br/><br/>Please use the following link to reset your password:<br/><br/>".$url."<br/><br/>Thank you for using " . $this->application_name . ".<br/></p></body></html>";
        //$this->SendEmailSendGrid($email, "Reset your password", $body, $this->support_email_address, $this->application_name . ' Support');
        $globalMergeVars = array(
            array('name' => 'USERNAME', 'content' => $displayName),
            array('name' => 'URL', 'content' => $url)
        );
        $this->SendEmailMandrill("reset-password", $globalMergeVars, $email, "Reset your password", $this->support_email_address, $this->application_name, "false");

        $result["result"] = 1;

        return json_encode($result);
    }

    public function ResetPassword()
    {
        $ret = $this->UpdatePassword($this->getCleanValueFromArguments('newPassword', true));

        if ($ret == -1)
        {
            return $this->JsonError("Your username or your token is not valid", 'ServerMessage20');
        }
        else if ($ret == -2)
        {
            return $this->JsonError("Your email or your token is not valid", 'ServerMessage17');
        }
        else if ($ret == -3)
        {
            return $this->JsonError("Your token has expired", 'ServerMessage18');
        }

        $result["result"] = 1;

        return json_encode($result);
    }
    
    private function UpdatePassword($newPass)
    {
        $token = $this->getCleanValueFromArguments('token', true);
        $useUsername = isset($this->arguments["username"]);

        if (!$useUsername)
        {
            $sql = "select count(\"UserUID\") from \"User\" where \"ResetPasswordToken\"='$token' and lower(\"Email\")='?email?'";
            $email = strtolower($this->getCleanValueFromArguments("email", true));
            $sql = str_replace("?email?", $email, $sql);
        }
        else
        {
            $sql = "select count(\"UserUID\") from \"User\" where \"ResetPasswordToken\"='$token' and lower(\"UserName\")='?username?'";
            $username = strtolower($this->getCleanValueFromArguments("username", true));
            $sql = str_replace("?username?", $username, $sql);
        }

        $count = $this->db->fetchValue($sql);
        
        if ($count != 1)
        {
            if ($useUsername)
                return -1;
            else
                return -2;
        }

        if (!$useUsername)
            $sql = "select \"UserUID\" from \"User\" where \"ResetPasswordToken\"='$token' and lower(\"Email\")='$email' and current_date<\"TokenExpireDate\"";
        else
            $sql = "select \"UserUID\" from \"User\" where \"ResetPasswordToken\"='$token' and lower(\"UserName\")='$username' and current_date<\"TokenExpireDate\"";
        
        $user_id = $this->db->fetchValue($sql);
        
        if (!$user_id)
        {
            return -3;
        }
        
        $pass = md5($newPass);

        # update password in social server
        $sql = "update \"User\" set \"Password\"='$pass' where \"UserUID\"='$user_id'";
        $this->db->exesql($sql);

        return 1;
    }

    public function ChangePassword()
    {
        $this->checkUser(true);

        $token = $this->getCleanValueFromArguments('token', true);
        $sql = "update \"User\" set \"ResetPasswordToken\"='$token', \"TokenExpireDate\"= current_date+interval '24 hours' where \"UserUID\"='$this->currentUserId'";
        $this->db->exesql($sql);

        return $this->ResetPassword();
    }

    public function SendEmail($checkUser = true, $checkToken=false)
    {
        if ($checkUser)
        {
            $this->checkUser($checkToken);

            # get display name and email address
            $sql = "select * from \"User\" where \"UserUID\"='$this->currentUserId'";
            $result = @pg_query($sql);
            while($line = pg_fetch_array($result))
            {
                $userName = $line['DisplayName'];
                $userEmail = $line['Email'];
            }
        }
        else
        {
            $userName = "Anonymous";
            $userEmail = $this->getCleanValueFromArguments('email', true);
        }


        $email_addresses = $this->arguments['to'];
        $subject = $this->arguments['subject'];
        $message = $this->arguments['message'];

        if ($email_addresses != '')
        {
            $finalresult["result"] = $this->SendEmailSendGrid($email_addresses, $subject, $message, $userEmail, $userName);
            
            if ($finalresult["result"])
            {
                $finalresult["msg"]='Email sent successfully';
                $finalresult["msgKey"] = 'ServerMessage54';
            }
            else
            {
                $finalresult["msg"]='Email sending failed';
                $finalresult["msgKey"] = 'ServerMessage55';
            }
            return json_encode($finalresult);
        }
        else
        {
            return $this->JsonError('You did not specify an email address', 'ServerMessage22');
        }
    }

    function SetUserDefaultSettings($user_id)
    {
        # Commented various assets that aren't used in 3d app

        # add default textures to user's drawer
#        $sql = "select \"TextureUID\" from \"Texture\" where \"OwnerUID\"='-1' order by \"TextureUID\"";
#        $defaultTextures = $this->db->exesqlAndReturnArray($sql);
#        if ($defaultTextures)
#        {
#            $sql = "insert into \"TextureDrawer\" (\"TextureUID\", \"UserUID\") values ('$defaultTextures[0]', '$user_id')";
#            for ($i=1; $i < count($defaultTextures); $i++)
#            {
#                $sql = $sql . ", ('$defaultTextures[$i]', '$user_id')";
#            }
#            $this->db->exesql($sql);
#        }

        # add default videos to user's drawer
#        $sql = "select \"VideoUID\" from \"Video\" where \"OwnerUID\"='-1' order by \"VideoUID\"";
#        $defaultVideos = $this->db->exesqlAndReturnArray($sql);
#        if ($defaultVideos)
#        {
#            $sql = "insert into \"VideoDrawer\" (\"VideoUID\", \"UserUID\") values ('$defaultVideos[0]', '$user_id')";
#            for ($i=1; $i < count($defaultVideos); $i++)
#            {
#                $sql = $sql . ", ('$defaultVideos[$i]', '$user_id')";
#            }
#            $this->db->exesql($sql);
#        }

        # add default spline shapes to user's shaper drawer
        $sql = "insert into \"MeshDrawer\" (\"MeshUID\", \"UserUID\") select \"MeshUID\", '$user_id' as constant from \"Mesh\" where \"OwnerUID\"='-1' and type = 0";
        $this->db->exesql($sql);

        # add default polygon meshes to shaper drawer (identified by tags)
        $sql = "insert into \"MeshDrawer\" (\"MeshUID\", \"UserUID\") select \"MeshUID\", '$user_id' as constant from \"Mesh\" where \"OwnerUID\"='-1' and type = 1 and \"MeshUID\" in (select \"MeshUID\" from \"MeshTag\" where \"TagText\" = 'shaper')";
        $this->db->exesql($sql);

        # add default toy designer shapes to user's drawer
        $sql = "insert into \"MeshDrawerToyDesigner\" (\"MeshUID\", \"UserUID\") select \"MeshUID\", '$user_id' as constant from \"Mesh\" where \"OwnerUID\"='-1' and type = 1 and \"MeshUID\" in (select \"MeshUID\" from \"MeshTag\" where \"TagText\" = 'toydesigner')";
        $this->db->exesql($sql);

        # add default shapes to user's templates
//        if ($defaultMeshes)
//        {
//            $sql = "insert into \"MeshTemplates\" (\"MeshUID\", \"UserUID\") values ('$defaultMeshes[0]', '$user_id')";
//            for ($i=1; $i < count($defaultMeshes); $i++)
//            {
//                $sql = $sql . ", ('$defaultMeshes[$i]', '$user_id')";
//            }
//            $this->db->exesql($sql);
//        }

        # add default groups to user's drawer
#        $sql = "select \"GroupUID\" from \"Group\" where \"UserUID\"='-1' order by \"GroupUID\"";
#        $defaultGroups = $this->db->exesqlAndReturnArray($sql);
#        if ($defaultGroups)
#        {
#            $sql = "insert into \"GroupDrawer\" (\"GroupUID\", \"UserUID\") values ('$defaultGroups[0]', '$user_id')";
#            for ($i=1; $i < count($defaultGroups); $i++)
#            {
#                $sql = $sql . ", ('$defaultGroups[$i]', '$user_id')";
#            }
#            $this->db->exesql($sql);
#        }

        # add default groups to user's templates
#        if ($defaultGroups)
#        {
#            $sql = "insert into \"GroupTemplates\" (\"GroupUID\", \"UserUID\") values ('$defaultGroups[0]', '$user_id')";
#            for ($i=1; $i < count($defaultGroups); $i++)
#            {
#                $sql = $sql . ", ('$defaultGroups[$i]', '$user_id')";
#            }
#            $this->db->exesql($sql);
#        }

        # add default swatches
#        $defaultSwatches = $this->db->sqlToArray("select \"TextureUID\", \"Color\", \"Color2\", \"Gradient\", \"TexGradient\", \"OutlineColor\", \"Outline\", \"Bound\", \"TexBound\", \"GradStyle\", \"TexGradStyle\", \"TexOffsetX\", \"TexOffsetY\", \"TexScaleX\", \"TexScaleY\" from \"Swatches\" where \"UserUID\"='-1' order by \"SwatchUID\"");
#        if ($defaultSwatches)
#        {
#            for ($j=0; $j < count($defaultSwatches); $j++)
#            {
#                $defaultSwatches[$j]['UserUID'] = $user_id;
#
#                $this->db->InsertAndReturnNewId("Swatches", $defaultSwatches[$j]);
#            }
#        }
    }

    public function ResetUserSettings()
    {
        $this->checkUser(true);

        #remove current values
        $this->db->exesql("delete from \"TextureDrawer\" where \"UserUID\"='$this->currentUserId'");
        $this->db->exesql("delete from \"VideoDrawer\" where \"UserUID\"='$this->currentUserId'");
        $this->db->exesql("delete from \"MeshDrawer\" where \"UserUID\"='$this->currentUserId'");
        $this->db->exesql("delete from \"MeshDrawerToyDesigner\" where \"UserUID\"='$this->currentUserId'");
//        $this->db->exesql("delete from \"MeshTemplates\" where \"UserUID\"='$this->currentUserId'");
        $this->db->exesql("delete from \"GroupDrawer\" where \"UserUID\"='$this->currentUserId'");
        $this->db->exesql("delete from \"GroupTemplates\" where \"UserUID\"='$this->currentUserId'");
        $this->db->exesql("delete from \"Swatches\" where \"UserUID\"='$this->currentUserId'");

        # set default values
        $this->SetUserDefaultSettings($this->currentUserId);

        $result["result"] = 1;

        return json_encode($result);
    }

    public function SetVariousUserDefaults()
    {
        $sql = "select \"UserUID\", \"UnlockCode\" from \"User\" where \"UnlockCode\" = 351";
        $defaultMeshes = $this->db->sqlToArray($sql);
        if ($defaultMeshes)
        {
            for ($i=0; $i < count($defaultMeshes); $i++)
            {
                $this->SetUserDefaultSettings($defaultMeshes[$i]['UserUID']);

                echo " $i" . $defaultMeshes[$i]['UserUID'] . ' ';
            }
        }
    }

    function SetExportFlag()
    {
        $this->checkUser(true);

        $canExportKeychain = $this->getCleanValueFromArguments('CanExportKeychain') == 'True';
        $canExportDoodler = $this->getCleanValueFromArguments('CanExportDoodler') == 'True';
        $canExportAvatar = $this->getCleanValueFromArguments('CanExportAvatar') == 'True';
        $canExportBlocker = $this->getCleanValueFromArguments('CanExportBlocker') == 'True';
        $canExportToyDesigner = $this->getCleanValueFromArguments('CanExportToyDesigner') == 'True';
        $canExportGears = $this->getCleanValueFromArguments('CanExportGears') == 'True';


        if ($canExportKeychain || $canExportDoodler || $canExportAvatar || $canExportBlocker || $canExportToyDesigner || $canExportGears)
        {
            $sql = "update \"User\" set (";
            $count = 0;
            if ($canExportKeychain)
            {
                $sql = $sql . "\"CanExportKeychain\"";
                $count++;
            }
            if ($canExportDoodler)
            {
                $sql = $sql . ($count > 0 ? ',' : '') . "\"CanExportDoodler\"";
                $count++;
            }
            if ($canExportAvatar)
            {
                $sql = $sql . ($count > 0 ? ',' : '') . "\"CanExportAvatar\"";
                $count++;
            }
            if ($canExportBlocker)
            {
                $sql = $sql . ($count > 0 ? ',' : '') . "\"CanExportBlocker\"";
                $count++;
            }
            if ($canExportToyDesigner)
            {
                $sql = $sql . ($count > 0 ? ',' : '') . "\"CanExportToyDesigner\"";
                $count++;
            }
            if ($canExportGears)
            {
                $sql = $sql . ($count > 0 ? ',' : '') . "\"CanExportGears\"";
                $count++;
            }

            $sql = $sql . ")=(";
            for ($i = 0; $i < $count; $i++)
            {
                $sql = $sql . ($i > 0 ? ',' : '') . "'t'";
            }
            $sql = $sql . ") where \"UserUID\" = '$this->currentUserId'";

            $this->db->exesql($sql);
        }

        $sql = "select \"CanExportKeychain\", \"CanExportDoodler\", \"CanExportAvatar\", \"CanExportBlocker\", \"CanExportToyDesigner\", \"CanExportGears\" from \"User\" where \"UserUID\"='$this->currentUserId'";
        $result = $this->db->sqlToArray($sql);
        if (!$result)
        {
            return $this->JsonError("Unknown error has occurred", 'ServerMessage23');
        }
        $result = $result[0];
        $result["result"] = 1;
        $result["UserUID"] = $this->currentUserId;

        return json_encode($result);
    }

    function SetSchoolPolicyFlags()
    {
        $this->checkUser(true, true);

        $sharingPolicy = $this->getCleanValueFromArguments('SharingPolicy'); // 1 = class, 2 = school, 3 = all schools, 4 = worldwide
        $viewingPolicy = $this->getCleanValueFromArguments('ViewingPolicy'); // 1 = class, 2 = school, 3 = all schools, 4 = worldwide
        $makerBotIntegration = $this->getCleanValueFromArguments('MakerBotIntegration'); // 0 = off, 1 = on
        $codeID = $this->getCleanValueFromArguments('CodeUID');

        if ($codeID != '' && ($sharingPolicy != '' || $viewingPolicy != '' || $makerBotIntegration != ''))
        {
            $sql = "update \"UnlockCodes\" set";
            $count = 0;
            if ($sharingPolicy != '')
            {
                $sql = $sql . " \"SharingPolicy\" = ?flag?";
                $sql = str_replace("?flag?", $sharingPolicy, $sql);
                $count++;
            }
            if ($viewingPolicy != '')
            {
                $sql = $sql . ($count > 0 ? ',' : '') . " \"ViewingPolicy\" = ?flag?";
                $sql = str_replace("?flag?", $viewingPolicy, $sql);
                $count++;
            }
            if ($makerBotIntegration != '')
            {
                $sql = $sql . ($count > 0 ? ',' : '') . " \"MakerBotIntegration\" = ?flag?";
                $sql = str_replace("?flag?", $makerBotIntegration, $sql);
                $count++;
            }
            $sql = $sql . " where codeuid = '?code?'";
            $sql = str_replace("?code?", $codeID, $sql);

            $queryResult = $this->db->exesql($sql);
            $result["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
            if ($result["result"] == 0)
            {
                $result["msg"] = "Unknown error has occurred while trying to update school privacy policies";
                $result["msgKey"] = 'ServerMessage56';
            }
            else
            {
                if ($sharingPolicy != '')
                {
                    $sql = "select u.\"UserUID\" from \"User\" u left join \"CodeCategories\" c on u.\"CodeCategory\" = c.\"CategoryUID\" where u.\"UnlockCode\" = ?code? and c.\"SharingPolicy\" = $this->scopeDefault";
                    $sql = str_replace("?code?", $codeID, $sql);

                    $students = $this->db->exesqlAndReturnArray($sql);
                    if ($students)
                    {
                        $idString = implode(',', $students);
                        if ($idString != "")
                            $this->db->exesql("update \"Design\" set \"SharingPolicy\" = $sharingPolicy where \"OwnerUID\" in ($idString)");
                    }
                }
            }
        }
        else
        {
            $result["result"] = 0;
            $result["msg"] = "School ID is missing or no privacy policies were set to be changed";
            $result["msgKey"] = 'ServerMessage57';
        }

        return json_encode($result);
    }

    function SetClassPolicyFlags()
    {
        $this->checkUser(true, true);

        $sharingPolicy = $this->getCleanValueFromArguments('SharingPolicy'); // 1 = class, 2 = school, 3 = all schools, 4 = worldwide
        $viewingPolicy = $this->getCleanValueFromArguments('ViewingPolicy'); // 1 = class, 2 = school, 3 = all schools, 4 = worldwide
        $makerBotIntegration = $this->getCleanValueFromArguments('MakerBotIntegration'); // 0 = off, 1 = on
        $categoryID = $this->getCleanValueFromArguments('CategoryUID');

        if ($categoryID != '' && ($sharingPolicy != '' || $viewingPolicy != '' || $makerBotIntegration != ''))
        {
            $sql = "update \"CodeCategories\" set";
            $count = 0;
            if ($sharingPolicy != '')
            {
                $sql = $sql . " \"SharingPolicy\" = ?flag?";
                $sql = str_replace("?flag?", $sharingPolicy, $sql);
                $count++;
            }
            if ($viewingPolicy != '')
            {
                $sql = $sql . ($count > 0 ? ', ' : ' ') . "\"ViewingPolicy\" = ?flag?";
                $sql = str_replace("?flag?", $viewingPolicy, $sql);
                $count++;
            }
            if ($makerBotIntegration != '')
            {
                $sql = $sql . ($count > 0 ? ', ' : ' ') . "\"MakerBotIntegration\" = ?flag?";
                $sql = str_replace("?flag?", $makerBotIntegration, $sql);
                $count++;
            }
            $sql = $sql . " where \"CategoryUID\" = '?category?'";
            $sql = str_replace("?category?", $categoryID, $sql);

            $queryResult = $this->db->exesql($sql);
            $result["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
            if ($result["result"] == 0)
            {
                $result["msg"] = "Unknown error has occurred while trying to update class privacy policies";
                $result["msgKey"] = 'ServerMessage58';
            }
            else
            {
                if ($sharingPolicy != '')
                {
                    $sql = "select \"UserUID\" from \"User\" where \"CodeCategory\" = '?category?'";
                    $sql = str_replace("?category?", $categoryID, $sql);

                    $students = $this->db->exesqlAndReturnArray($sql);
                    if ($students)
                    {
                        $idString = implode(',', $students);
                        if ($idString != "")
                            $this->db->exesql("update \"Design\" set \"SharingPolicy\" = $sharingPolicy where \"OwnerUID\" in ($idString)");
                    }
                }
            }
        }
        else
        {
            $result["result"] = 0;
            $result["msg"] = "Class ID is missing or no privacy policies were set to be changed";
            $result["msgKey"] = 'ServerMessage59';
        }

        return json_encode($result);
    }

    function GetPolicyFlags()
    {
        $this->checkUser(true);

        $result["result"] = 1;

        $categoryID = $this->getCleanValueFromArguments('CategoryUID');
        $codeID = $this->getCleanValueFromArguments('CodeUID');

        //if ($categoryID == '' && $codeID == '')
        //{
        //    $sql = "select \"UnlockCode\", \"CodeCategory\" from \"User\" where \"UserUID\"='$this->currentUserId'";
        //    $codes = $this->db->fetchArray($sql);
        //    if ($codes)
        //    {
        //        if ($codes["UnlockCode"] != "0")
        //            $codeID = $codes["UnlockCode"];
        //        if ($codes["CodeCategory"] != "0")
        //            $categoryID = $codes["CodeCategory"];
        //    }
        //}

        if ($categoryID == "")
        {
            if ($codeID == "")
            {
                $result["result"] = 0;
                $result["msg"] = "No unlock code and class ID provided.";
                $result["msgKey"] = 'ServerMessage60';
            }
            else
            {
                $sql = "select \"SharingPolicy\", \"ViewingPolicy\", \"MakerBotIntegration\" from \"UnlockCodes\" where codeuid = '?code?'";
                $sql = str_replace("?code?", $codeID, $sql);
                $policyArray = $this->db->fetchArray($sql);

                if ($policyArray)
                {
                    $result["SchoolSharingPolicy"] = $policyArray["SharingPolicy"];
                    $result["SchoolViewingPolicy"] = $policyArray["ViewingPolicy"];
                    $result["SchoolMakerBotIntegration"] = $policyArray["MakerBotIntegration"];
                    $result["ClassSharingPolicy"] = $this->scopeDefault;
                    $result["ClassViewingPolicy"] = $this->scopeDefault;
                    $result["ClassMakerBotIntegration"] = $this->scopeDefault;
                }
                else
                {
                    $result["result"] = 0;
                    $result["msg"] = "Unexpected error has occurred.";
                    $result["msgKey"] = 'ServerMessage61';
                }
            }
        }
        else
        {
            if ($categoryID == 0)
            {
                $sql = "select \"CodeUID\" from \"CodeCategories\" where \"CategoryUID\" = '?category?'";
                $sql = str_replace("?category?", $categoryID, $sql);
                $codeID = $this->db->fetchValue($sql);
                if ($codeID && $codeID > 0)
                {
                    $policyArray = $this->db->fetchArray("select \"SharingPolicy\", \"ViewingPolicy\", \"MakerBotIntegration\" from \"UnlockCodes\" where codeuid = '".$codeID."'");

                    if ($policyArray)
                    {
                        $policyArray["ClassSharingPolicy"] = $this->scopeDefault;
                        $policyArray["ClassViewingPolicy"] = $this->scopeDefault;
                        $policyArray["ClassMakerBotIntegration"] = $this->scopeDefault;
                    }
                }
                else
                {
                    $policyArray = false;
                }
            }
            else
            {
                $policyArray = $this->db->fetchArray("select a.\"SharingPolicy\" as \"ClassSharingPolicy\", a.\"ViewingPolicy\" as \"ClassViewingPolicy\", a.\"MakerBotIntegration\" as \"ClassMakerBotIntegration\", b.\"SharingPolicy\" as \"SchoolSharingPolicy\", b.\"ViewingPolicy\" as \"SchoolViewingPolicy\", b.\"MakerBotIntegration\" as \"SchoolMakerBotIntegration\" from \"CodeCategories\" a, \"UnlockCodes\" b where a.\"CategoryUID\" = '".$categoryID."' and b.codeuid = a.\"CodeUID\"");
            }

            if ($policyArray)
            {
                $result["SchoolSharingPolicy"] = $policyArray["SchoolSharingPolicy"];
                $result["SchoolViewingPolicy"] = $policyArray["SchoolViewingPolicy"];
                $result["SchoolMakerBotIntegration"] = $policyArray["SchoolMakerBotIntegration"];
                $result["ClassSharingPolicy"] = $policyArray["ClassSharingPolicy"];
                $result["ClassViewingPolicy"] = $policyArray["ClassViewingPolicy"];
                $result["ClassMakerBotIntegration"] = $policyArray["ClassMakerBotIntegration"];
            }
            else
            {
                $result["result"] = 0;
                $result["msg"] = "Unexpected error has occurred.";
                $result["msgKey"] = 'ServerMessage61';
            }
        }

        return json_encode($result);
    }

    function VerifyCode()
    {
        $this->checkUser(true);

        $code = $this->getCleanValueFromArguments('Code', true);
        $code = strtolower($code);
        if ($code == "")
        {
            $result["result"] = 0;
            $result["msg"] = "No unlock code provided.";
            $result["msgKey"] = 'ServerMessage62';
        }
        else
        {
            $sql = "select \"codeuid\", \"Description\", \"UnlocksAvailable\" from \"UnlockCodes\" where \"Code\"='?code?'";
            $sql = str_replace("?code?", $code, $sql);
            $codeArray = $this->db->sqlToArray($sql);
            if ($codeArray)
            {
                $codeArray = $codeArray[0];

                $sql = "select count(*) from \"User\" where \"UnlockCode\"='".$codeArray["codeuid"]."'";
                $codesUsed = $this->db->fetchValue($sql);
                if ($codesUsed < (int)$codeArray["UnlocksAvailable"])
                {
                    $sql = "select \"CategoryUID\", \"CategoryName\" from \"CodeCategories\" where \"CodeUID\" = '".$codeArray["codeuid"]."' order by \"CategoryUID\"";
                    $categoryArray = $this->db->sqlToArray($sql);

                    if ($categoryArray)
                    {
                        $categoryID = $categoryArray[0]["CategoryUID"];
                        $categoryName = $categoryArray[0]["CategoryName"];
                    }
                    else
                    {
                        $categoryID = 0;
                        $categoryName = "";
                    }

                    date_default_timezone_set("UTC");
                    $now = new DateTime;
                    $nowStr = $now->format('Y-m-d H:i:s');
        
                    $sql = "update \"User\" set (\"UnlockCode\", unlock_code_activation_date, \"CodeCategory\", \"CanExportKeychain\", \"CanExportDoodler\", \"CanExportAvatar\", \"CanExportBlocker\", \"CanExportToyDesigner\", \"CanExportGears\") = ('".$codeArray["codeuid"]."', '$nowStr', '".$categoryID."', 't', 't', 't', 't', 't', 't') where \"UserUID\" = '$this->currentUserId'";
                    $queryResult = $this->db->exesql($sql);
                    $querySucceeded = pg_affected_rows($queryResult) > 0;
                    if ($querySucceeded)
                    {
                        if ($categoryID != 0)
                        {
                            $policyArray = $this->db->fetchArray("select a.\"SharingPolicy\" as \"ClassSharingPolicy\", a.\"ViewingPolicy\" as \"ClassViewingPolicy\", a.\"MakerBotIntegration\" as \"ClassMakerBotIntegration\", b.\"SharingPolicy\" as \"SchoolSharingPolicy\", b.\"ViewingPolicy\" as \"SchoolViewingPolicy\", b.\"MakerBotIntegration\" as \"SchoolMakerBotIntegration\" from \"CodeCategories\" a, \"UnlockCodes\" b where a.\"CategoryUID\" = '".$categoryID."' and b.codeuid = a.\"CodeUID\"");
                        }
                        else
                        {
                            // no classes found so getting only school policies (fake class policies)
                            $policyArray = $this->db->fetchArray("select \"SharingPolicy\" as \"ClassSharingPolicy\", \"ViewingPolicy\" as \"ClassViewingPolicy\", \"MakerBotIntegration\" as \"ClassMakerBotIntegration\", \"SharingPolicy\" as \"SchoolSharingPolicy\", \"ViewingPolicy\" as \"SchoolViewingPolicy\", \"MakerBotIntegration\" as \"SchoolMakerBotIntegration\" from \"UnlockCodes\" where codeuid = '".$codeArray["codeuid"]."'");
                        }

                        if ($policyArray)
                        {
                            $result["SharingPolicy"] = $policyArray["ClassSharingPolicy"] != $this->scopeDefault ? $policyArray["ClassSharingPolicy"] : $policyArray["SchoolSharingPolicy"];
                            $result["ViewingPolicy"] = $policyArray["ClassViewingPolicy"] != $this->scopeDefault ? $policyArray["ClassViewingPolicy"] : $policyArray["SchoolViewingPolicy"];
                            $result["MakerBotIntegration"] = $policyArray["ClassMakerBotIntegration"] != "-1" ? $policyArray["ClassMakerBotIntegration"] : $policyArray["SchoolMakerBotIntegration"];
                        }
                        else
                        {
                            $result["SharingPolicy"] = $this->scopeClass;
                            $result["ViewingPolicy"] = $this->scopeClass;
                            $result["MakerBotIntegration"] = "0";
                        }

                        $this->db->exesql("update \"Design\" set \"SharingPolicy\" = " . $result["SharingPolicy"] . " where \"OwnerUID\" = $this->currentUserId");

                        $result["result"] = 1;
                        $result["CodeUID"] = $codeArray["codeuid"];
                        $result["CodeDescription"] = $codeArray["Description"];
                        $result["CategoryUID"] = $categoryID;
                        if ($categoryArray)
                        {
                            $result["Categories"] = $categoryArray;
                        }
                    }
                    else
                    {
                        $result["result"] = 0;
                        $result["msg"] = "Unknown error occurred while updating user data.";
                        $result["msgKey"] = 'ServerMessage63';
                    }
                }
                else
                {
                    $result["result"] = 0;
                    $result["msg"] = "You cannot unlock more accounts with this code, the limit has been reached.";
                    $result["msgKey"] = 'ServerMessage64';
                }
            }
            else
            {
                $result["result"] = 0;
                $result["msg"] = "Provided code was not found.";
                $result["msgKey"] = 'ServerMessage65';
            }
        }

        return json_encode($result);
    }

    function SetCategory()
    {
        $this->checkUser(true);

        $categoryID = $this->getCleanValueFromArguments('CategoryUID', true);
        if ($categoryID == "")
        {
            $result["result"] = 0;
            $result["msg"] = "Category info is missing.";
            $result["msgKey"] = 'ServerMessage66';
        }
        else
        {
            $sql = "update \"User\" set \"CodeCategory\" = '?category?' where \"UserUID\" = $this->currentUserId";
            $sql = str_replace("?category?", $categoryID, $sql);
            $queryResult = $this->db->exesql($sql);
            $querySucceeded = pg_affected_rows($queryResult) > 0;
            if ($querySucceeded)
            {
                $result["result"] = 1;
                $result["CategoryUID"] = $categoryID;

                if ($categoryID != 0)
                {
                    $policyArray = $this->db->fetchArray("select a.\"SharingPolicy\" as \"ClassSharingPolicy\", a.\"ViewingPolicy\" as \"ClassViewingPolicy\", a.\"MakerBotIntegration\" as \"ClassMakerBotIntegration\", b.\"SharingPolicy\" as \"SchoolSharingPolicy\", b.\"ViewingPolicy\" as \"SchoolViewingPolicy\", b.\"MakerBotIntegration\" as \"SchoolMakerBotIntegration\" from \"CodeCategories\" a, \"UnlockCodes\" b where a.\"CategoryUID\" = '".$categoryID."' and b.codeuid = a.\"CodeUID\"");

                    if ($policyArray)
                    {
                        $result["SharingPolicy"] = $policyArray["ClassSharingPolicy"] != $this->scopeDefault ? $policyArray["ClassSharingPolicy"] : $policyArray["SchoolSharingPolicy"];
                        $result["ViewingPolicy"] = $policyArray["ClassViewingPolicy"] != $this->scopeDefault ? $policyArray["ClassViewingPolicy"] : $policyArray["SchoolViewingPolicy"];
                        $result["MakerBotIntegration"] = $policyArray["ClassMakerBotIntegration"] != "-1" ? $policyArray["ClassMakerBotIntegration"] : $policyArray["SchoolMakerBotIntegration"];
                    }
                    else
                    {
                        $result["SharingPolicy"] = $this->scopeClass;
                        $result["ViewingPolicy"] = $this->scopeClass;
                        $result["MakerBotIntegration"] = "0";
                    }
                }
                else
                {
                    $schoolCode = $this->db->fetchValue("select \"UnlockCode\" from \"User\" where \"UserUID\" = $this->currentUserId");
                    if ($schoolCode && $schoolCode != 0)
                    {
                        $policyArray = $this->db->fetchArray("select \"SharingPolicy\", \"ViewingPolicy\", \"MakerBotIntegration\" from \"UnlockCodes\" where codeuid = $schoolCode");
                    }
                    else
                        $policyArray = false;

                    if ($policyArray)
                    {
                        $result["SharingPolicy"] = $policyArray["SharingPolicy"];
                        $result["ViewingPolicy"] = $policyArray["ViewingPolicy"];
                        $result["MakerBotIntegration"] = $policyArray["MakerBotIntegration"];
                    }
                    else
                    {
                        $result["SharingPolicy"] = $this->scopeWorldwide;
                        $result["ViewingPolicy"] = $this->scopeWorldwide;
                        $result["MakerBotIntegration"] = "1";
                    }
                }

                $this->db->exesql("update \"Design\" set \"SharingPolicy\" = " . $result["SharingPolicy"] . " where \"OwnerUID\" = $this->currentUserId");
            }
            else
            {
                $result["result"] = 0;
                $result["msg"] = "Unknown error occurred while updating user data.";
                $result["msgKey"] = 'ServerMessage63';
            }
        }

        return json_encode($result);
    }

    function SubmitDesignToCompetition()
    {
        $competition_id = $this->getCleanValueFromArguments("competition_id");
        $design_id = $this->getCleanValueFromArguments("design_id");
        $description = $this->getCleanValueFromArguments("description");
        $age_group = $this->getCleanValueFromArguments("age_group");
        $id_to_replace = $this->getCleanValueFromArguments("id_to_replace");

        $sql = "select count(*) from competitions where id = '$competition_id'";
        $count = $this->db->fetchValue($sql);

        if ($count == 0)
        {
            $result["result"] = 0;
            $result["msg"] = "Couldn't find a competition with the id $competition_id";
        }
        else
        {
            date_default_timezone_set("UTC");
            $currentTime =  date("Y-m-d H:i:s", time());
            $submit = "true";
            if ($id_to_replace)
            {
                // check if we are just updating the current design
                if ($design_id == $id_to_replace)
                {

                    $submit = "false";
                    // can just update and return here
                    if ($age_group)
                        $sql = "update competition_submissions set (description, age_group, updated_at) = ('$description', '$age_group', '$currentTime') where competition_id = '$competition_id' and design_id = '$design_id'";
                    else
                        $sql = "update competition_submissions set (description, updated_at) = ('$description', '$currentTime') where competition_id = '$competition_id' and design_id = '$design_id'";

                    $queryResult = $this->db->exesql($sql);
                    $result["result"] = 1;
                    $result["description"] = $description;
                    $result["updated"] = "true";
                }
                else
                {
                    $sql = "delete from competition_submissions where design_id = '$id_to_replace' and competition_id = '$competition_id'";
                    $queryResult = $this->db->exesql($sql);

                    if (pg_affected_rows($queryResult) == 0)
                    {
                        $result["result"] = 0;
                        $result["msg"] = "failed to replace existing design";
                        $submit = "false";
                    }
                    else
                    {
                        $result["removed_id"] = $id_to_replace;
                        // remove the existing competition tag from the design
                        $this->db->exesql("delete from \"DesignTag\" where \"DesignUID\"= '$id_to_replace' and \"TagText\" = '_cid$competition_id'");
                    }
                }
            }
            else
            {
                $sql = "select \"OwnerUID\" from \"Design\" where \"DesignUID\" = '$design_id'";
                $userId = $this->db->fetchValue($sql);

                // check to see if the user already has a submission for this competition
                $sql = "select design_id from competition_submissions where competition_id = '$competition_id' and design_id in (select \"DesignUID\" from \"Design\" where \"OwnerUID\" = '$userId')";
                $existingSubmission = $this->db->fetchValue($sql);

                if ($existingSubmission)
                {
                    $sql = "select \"DisplayName\" from \"Design\" where \"DesignUID\" = '$existingSubmission'";
                    $designName = $this->db->fetchValue($sql);
                    $result["result"] = 0;
                    $result["ExistingSubmissionId"] = $existingSubmission;
                    $result["ExistingSubmissionName"] = $designName;
                    $submit = "false";
                }
            }

            if ($submit == "true")
            {
                if ($age_group)
                    $sql = "insert into competition_submissions (competition_id, design_id, description, age_group, created_at) values ('$competition_id', '$design_id', '$description', '$age_group', '$currentTime')";
                else
                    $sql = "insert into competition_submissions (competition_id, design_id, description, created_at) values ('$competition_id', '$design_id', '$description', '$currentTime')";
                $queryResult = $this->db->exesql($sql);
                $querySucceeded = pg_affected_rows($queryResult) > 0;

                if ($querySucceeded)
                {
                    $this->AddSingleTagToLevel("_cid$competition_id", $design_id, "true");
                    $result["result"] = 1;
                    $result["description"] = $description;

                    // make this design public since it's been submit
                    $sql = "update \"Design\" set (\"SharingPolicy\") = ('$this->scopeWorldwide') where \"DesignUID\" = '$design_id'";
                    $this->db->exesql($sql);

                    // we return the id of the competition entry also
                    $sql = "select id from competition_submissions where competition_id = '$competition_id' and design_id = '$design_id'";
                    $submission_id = $this->db->fetchValue($sql);
                    $result["submission_id"] = $submission_id;
                }
                else
                {
                    $result["result"] = 0;
                    $result["msg"] = "SubmitDesignToCompetition failed insert on table";
                }
            }
        }

        return json_encode($result);
    }

    function GetCompetitionEntries()
    {
        $competition_id = $this->getCleanValueFromArguments("competition_id");
        $num_to_return = $this->getCleanValueFromArguments("num_to_return");

        $sql = "select design_id, description from competition_submissions where competition_id = $competition_id order by random() limit $num_to_return";
        $submissionsArray = $this->db->sqlToArray($sql);
        if ($submissionsArray)
        {
            $result["Competition_Submissions"] = $submissionsArray;
            $result["result"] = 1;
        }
        else
            $result["result"] = 0;

        return json_encode($result);
    }

    function FetchCompetitionEntryDescription()
    {
        $competition_id = $this->getCleanValueFromArguments("competition_id");
        $design_id = $this->getCleanValueFromArguments("design_id");

        // START won't work on old version which doesn't pass hall_of_fame argument
        //$hall_of_fame = $this->getCleanValueFromArguments("hall_of_fame");
        //if ($hall_of_fame == "True")
        //    $sql = "select description from competition_submissions where design_id = '$design_id' and status is not null";
        //else
        // END
            $sql = "select description from competition_submissions where competition_id = '$competition_id' and design_id = '$design_id'";

        $description = $this->db->fetchValue($sql);

        if ($description)
        {
            $result["result"] = 1;
            $result["description"] = $description;
            $result["design_id"] = $design_id;
        }
        else
        {
            // if we didn't get a result, get a description if it's a winner
            $sql = "select description from competition_submissions where design_id = '$design_id' and status is not null";
            $winner_description = $this->db->fetchValue($sql);
            if ($winner_description)
            {
                // get the judges comment if we found it
                //$sql = "select judges_comment from competition_submissions where design_id = '$design_id' and status is not null";
                //$judges_comment = $this->db->fetchValue($sql);
                // get an array of the winning designs competition info
                $sql = "select a.teacher_email_title, b.judges_comment from competitions a, competition_submissions b where a.id = b.competition_id and b.design_id = '$design_id' and b.status is not null";
                $win_info = $this->db->fetchArray($sql);

                $result["result"] = 1;
                $result["description"] = $winner_description;
                $result["design_id"] = $design_id;
                if ($win_info)
                    $result["hall_of_fame_array"] = $win_info;
            }
            else
                $result["result"] = 0;
        }

        return json_encode($result);
    }

    function GetDesignCompetitionStatus()
    {
        // TODO when we have multiple competitions, we should return the HIGHEST status this design has achieved
        // since it could be entered in multiple competitions
        // although maybe we want to return ALL results... could display multiple runner up ribbons and a winner ribbon for example
        $designUID = $this->getCleanValueFromArguments("design_id");
        if ($designUID)
        {
            $result["result"] = 1;
            $sql = "select status from competition_submissions where design_id = '$designUID'";
            $fetchedStatus = $this->db->fetchValue($sql);
            if ($fetchedStatus)
            {
                $result["status"] = $fetchedStatus;
                $result["design_id"] = $designUID;
            }
        }
        else
            $result["result"] = 0;

        return json_encode($result);
    }

    function CreateUnlockCodes()
    {
        $numCodes = $this->getCleanValueFromArguments('num');
        if ($numCodes == null)
            $numCodes = 3;

        $prefix = $this->getCleanValueFromArguments('prefix');
        if ($prefix == null)
            $prefix = '';

        $description = $this->getCleanValueFromArguments('description');
        if ($description == null)
            $description = 'untitled';

        $unlocks = $this->getCleanValueFromArguments('unlocks');
        if ($unlocks == null)
            $unlocks = 3;

        $category = $this->getCleanValueFromArguments('category');
        if ($category == null)
            $category = 'Not Applicable';


        $randomCharacters = 'abcdefghijklmnopqrstuvwxyz0123456789';

        for ($i=0; $i<$numCodes; $i++)
        {
            $code = strtolower($prefix);

            for ($j = strlen($prefix); $j<8; $j++)
                $code .= $randomCharacters[rand(0, strlen($randomCharacters) - 1)];

            $sql = "insert into \"UnlockCodes\" (\"Code\", \"Description\", \"UnlocksAvailable\") values ('$code', '$description', $unlocks)";
            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
                die($this->JsonError("error inserting unlock code into db", ''));

            $sql = "select codeuid from \"UnlockCodes\" where \"Code\"='$code'";
            $codeuid = $this->db->fetchValue($sql);
            
            $sql = "insert into \"CodeCategories\" (\"CategoryName\", \"CodeUID\") values ('$category', $codeuid)";
            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
                die($this->JsonError("error inserting category into db", ''));

            $filename = 'unlockcodes.csv';
            $current = file_get_contents($filename);
            // Append a new person to the file
            $current .= "$code\n";
            // Write the contents back to the file
            file_put_contents($filename, $current);
        }
    }

    // TODO: remove this function after updating client app
    function LoginOrCreateUser()
    {
        $email = strtolower($this->getCleanValueFromArguments('email', true));
        if ($email != '')
        {
            $sql = "select count(*) from \"User\" where \"Email\"='?email?'";
            $sql = str_replace("?email?", $email, $sql);
            $count = $this->db->fetchValue($sql);
            if ($count == 0)
            {
                $this->CreateAccount();
            }
            $count = $this->db->fetchValue($sql);
            if ($count == 0)
            {
                $result["msg"] = "User was not found in the database";
                $result["msgKey"] = 'ServerMessage67';
                $result["result"] = 0;

                return json_encode($result);
            }
            else
            {
                // TODO: change this back after updating client app
                //$this->arguments['password'] = $this->arguments['passwordToLogin'];
                //return $this->LoginUser();
                return $this->LoginDefaultUser();
            }
        }
        else
        {
            die($this->JsonError("Login data is missing", 'ServerMessage24'));
        }
    }

    // TODO: remove this function after updating client app
    function LoginDefaultUser()
    {
        $sql = "select \"Password\", \"UserUID\" from \"User\" where lower(\"Email\")='?email?'";
        $email = strtolower($this->getCleanValueFromArguments("email", true));
        $sql = str_replace("?email?", $email, $sql);

        $result = $this->db->fetchArray($sql);
        $entryToTest = $result['Password'];

        $token = $this->getCleanValueFromArguments("token", true);
        $expectedHash = $this->arguments['passwordToLogin'];
        $hash = md5($token.$entryToTest);

        $this->currentUserId = $result['UserUID'];

        if ($hash !== $expectedHash)
        {
            $password = md5($this->getCleanValueFromArguments('password', true));

            $hash = md5($token.$password);
            if ($hash !== $expectedHash)
            {
                die($this->JsonError("Password is incorrect", 'ServerMessage25'));
            }

            $sql = "update \"User\" set \"Password\" = '$password' where \"UserUID\" = '$this->currentUserId'";
            $this->db->exesql($sql);
        }

        $sql = "select \"Email\", \"UserName\", \"DisplayName\", \"Password\", \"PictureUrl\", \"Description\", \"Location\", \"AccountCreationDate\",\"CanExportKeychain\", \"CanExportDoodler\", \"CanExportAvatar\", \"CanExportBlocker\", \"CanExportToyDesigner\", \"CanExportGears\", \"UnlockCode\", \"CodeCategory\" from \"User\" where \"UserUID\"='$this->currentUserId'";

        $result = $this->db->sqlToArray($sql);
        if (!$result)
        {
            return $this->JsonError("User cannot be found", 'ServerMessage1');
        }
        $result = $result[0];
        $result["UserUID"] = $this->currentUserId;

        if ((int)$result["UnlockCode"] > 0)
        {
            if ((int)$result["CodeCategory"] != 0)
            {
                $policyArray = $this->db->fetchArray("select a.\"SharingPolicy\" as \"ClassSharingPolicy\", a.\"ViewingPolicy\" as \"ClassViewingPolicy\", a.\"MakerBotIntegration\" as \"ClassMakerBotIntegration\", b.\"SharingPolicy\" as \"SchoolSharingPolicy\", b.\"ViewingPolicy\" as \"SchoolViewingPolicy\", b.\"MakerBotIntegration\" as \"SchoolMakerBotIntegration\" from \"CodeCategories\" a, \"UnlockCodes\" b where a.\"CategoryUID\" = '".$result["CodeCategory"]."' and b.codeuid = a.\"CodeUID\"");
            }
            else
            {
                // no classes found so getting only school policies (fake class policies)
                $policyArray = $this->db->fetchArray("select \"SharingPolicy\" as \"ClassSharingPolicy\", \"ViewingPolicy\" as \"ClassViewingPolicy\", \"MakerBotIntegration\" as \"ClassMakerBotIntegration\", \"SharingPolicy\" as \"SchoolSharingPolicy\", \"ViewingPolicy\" as \"SchoolViewingPolicy\", \"MakerBotIntegration\" as \"SchoolMakerBotIntegration\" from \"UnlockCodes\" where codeuid = '".$result["UnlockCode"]."'");
            }

            if ($policyArray)
            {
                $result["SharingPolicy"] = $policyArray["ClassSharingPolicy"] != $this->scopeDefault ? $policyArray["ClassSharingPolicy"] : $policyArray["SchoolSharingPolicy"];
                $result["ViewingPolicy"] = $policyArray["ClassViewingPolicy"] != $this->scopeDefault ? $policyArray["ClassViewingPolicy"] : $policyArray["SchoolViewingPolicy"];
                $result["MakerBotIntegration"] = $policyArray["ClassMakerBotIntegration"] != "-1" ? $policyArray["ClassMakerBotIntegration"] : $policyArray["SchoolMakerBotIntegration"];
            }
            else
            {
                $result["SharingPolicy"] = $this->scopeClass;
                $result["ViewingPolicy"] = $this->scopeClass;
                $result["MakerBotIntegration"] = "0";
            }

            $result["CodeDescription"] = $this->db->fetchValue("select \"Description\" from \"UnlockCodes\" where \"codeuid\"='".$result["UnlockCode"]."'");
            $categoryArray = $this->db->sqlToArray("select \"CategoryUID\", \"CategoryName\" from \"CodeCategories\" where \"CodeUID\" = '".$result["UnlockCode"]."' order by \"CategoryUID\"");
            if ($categoryArray)
            {
                $result["Categories"] = $categoryArray;
            }
        }
        else
        {
            $result["SharingPolicy"] = $this->scopeWorldwide;
            $result["ViewingPolicy"] = $this->scopeWorldwide;
            $result["MakerBotIntegration"] = "1";
        }

        date_default_timezone_set("UTC");
        $currentTime =  date("Y-m-d H:i:s", time());

        $token = md5(mt_rand());
        $result["SessionToken"] = $token;

        # update session token in social server
        $sql = "update \"User\" set (\"SessionToken\", \"LastTimeLoggedIn\")=('$token', '$currentTime') where \"UserUID\"='$this->currentUserId'";
        $this->db->exesql($sql);

        return json_encode($result);
    }

//    function LoginUser($isNew = false)
//    {
//        $this->checkUser();

//        $sql = "select \"Email\", \"UserName\", \"DisplayName\", \"Password\", \"PictureUrl\", \"Description\", \"Location\", \"AccountCreationDate\", \"CanExportKeychain\", \"CanExportDoodler\", \"CanExportAvatar\", \"CanExportBlocker\", \"CanExportToyDesigner\", \"CanExportGears\", \"UnlockCode\", \"CodeCategory\", makerbot_username, disabled_competition_id from \"User\" where \"UserUID\"='$this->currentUserId'";

//        $result = $this->db->sqlToArray($sql);
//        if (!$result)
//        {
//            return $this->JsonError("User cannot be found", 'ServerMessage1');
//        }
//        $result = $result[0];
//        $result["isNew"] = $isNew ? 't' : 'f';
//        $result["UserUID"] = $this->currentUserId;

        // hack to make sure this function returns 0 for unlock code if it is not set (to keep compatibility before client version 2.6)
//        if ($result["UnlockCode"] === null)
//            $result["UnlockCode"] = '0';

//        if ((int)$result["UnlockCode"] > 0)
//        {
//            if ((int)$result["CodeCategory"] != 0)
//            {
//                $policyArray = $this->db->fetchArray("select a.\"SharingPolicy\" as \"ClassSharingPolicy\", a.\"ViewingPolicy\" as \"ClassViewingPolicy\", a.\"MakerBotIntegration\" as \"ClassMakerBotIntegration\", b.\"SharingPolicy\" as \"SchoolSharingPolicy\", b.\"ViewingPolicy\" as \"SchoolViewingPolicy\", b.\"MakerBotIntegration\" as \"SchoolMakerBotIntegration\" from \"CodeCategories\" a, \"UnlockCodes\" b where a.\"CategoryUID\" = '".$result["CodeCategory"]."' and b.codeuid = a.\"CodeUID\"");
//            }
//            else
//            {
                // no classes found so getting only school policies (fake class policies)
//                $policyArray = $this->db->fetchArray("select \"SharingPolicy\" as \"ClassSharingPolicy\", \"ViewingPolicy\" as \"ClassViewingPolicy\", \"MakerBotIntegration\" as \"ClassMakerBotIntegration\", \"SharingPolicy\" as \"SchoolSharingPolicy\", \"ViewingPolicy\" as \"SchoolViewingPolicy\", \"MakerBotIntegration\" as \"SchoolMakerBotIntegration\" from \"UnlockCodes\" where codeuid = '".$result["UnlockCode"]."'");
//            }

//            if ($policyArray)
//            {
//                $result["SharingPolicy"] = $policyArray["ClassSharingPolicy"] != $this->scopeDefault ? $policyArray["ClassSharingPolicy"] : $policyArray["SchoolSharingPolicy"];
//                $result["ViewingPolicy"] = $policyArray["ClassViewingPolicy"] != $this->scopeDefault ? $policyArray["ClassViewingPolicy"] : $policyArray["SchoolViewingPolicy"];
//                $result["MakerBotIntegration"] = $policyArray["ClassMakerBotIntegration"] != "-1" ? $policyArray["ClassMakerBotIntegration"] : $policyArray["SchoolMakerBotIntegration"];
//            }
//            else
//            {
//                $result["SharingPolicy"] = $this->scopeClass;
//                $result["ViewingPolicy"] = $this->scopeClass;
//                $result["MakerBotIntegration"] = "0";
//            }

//            $result["CodeDescription"] = $this->db->fetchValue("select \"Description\" from \"UnlockCodes\" where \"codeuid\"='".$result["UnlockCode"]."'");
//            $categoryArray = $this->db->sqlToArray("select \"CategoryUID\", \"CategoryName\" from \"CodeCategories\" where \"CodeUID\" = '".$result["UnlockCode"]."' order by \"CategoryUID\"");
//            if ($categoryArray)
//            {
//                $result["Categories"] = $categoryArray;
//            }
//        }
//        else
//        {
//            $result["SharingPolicy"] = $this->scopeWorldwide;
//            $result["ViewingPolicy"] = $this->scopeWorldwide;
//            $result["MakerBotIntegration"] = "1";
//        }

//        # get app version or empty string if none passed
//        $appVersionString = $this->getCleanValueFromArguments('version');

//        if ($appVersionString == null)
//        {
//            $appVersionNum = 0;
//        }
//        else
//        {
//            $vPos = strpos($appVersionString, 'v');
//            $appVersionNum = substr($appVersionString, $vPos+1);
//            if ($appVersionNum > 1.7)
//            {
//                # add default 3d shapes to user's drawer
//                $sql = "select \"MeshUID\" from \"Mesh\" where \"OwnerUID\"='-1' and type = 1 and \"MeshUID\" in (select \"MeshUID\" from \"MeshTag\" where \"TagText\" = 'shaper') order by \"MeshUID\"";

//                $defaultMeshes = $this->db->exesqlAndReturnArray($sql);
//                if ($defaultMeshes)
//                {
//                    # check that the meshes aren't already in the drawer
//                    $current3dMeshes = $this->db->sqlToArray("select \"MeshUID\" from \"MeshDrawer\" where \"UserUID\"='$this->currentUserId'");


//                    $numMeshes = 0;
//                    for ($i=0; $i < count($defaultMeshes); $i++)
//                    {
//                        $found = false;

//                        if ($current3dMeshes)
//                        {
//                            for ($j=0; $j < count($current3dMeshes); $j++)
//                            {
//                                if ($defaultMeshes[$i] == $current3dMeshes[$j]['MeshUID'])
//                                {
//                                    $found = true;
//                                    break;
//                                }
//                            }
//                        }

//                        if (!$found)
//                        {
//                            if ($numMeshes == 0)
//                                $sql = "insert into \"MeshDrawer\" (\"MeshUID\", \"UserUID\") values ('$defaultMeshes[$i]', '$this->currentUserId')";
//                            else
//                                $sql = $sql . ", ('$defaultMeshes[$i]', '$this->currentUserId')";

//                            $numMeshes = $numMeshes + 1;
//                        }
//                    }

//                    if ($numMeshes > 0)
//                        $this->db->exesql($sql);
//                }
//           }
//        }


//        $userLanguage = $this->getCleanValueFromArguments("language");
//        if ($userLanguage)
//        {
            //if ((int)$result["UnlockCode"] > 0) //&& $result["SharingPolicy"] == 4)
            //{
                // look for a valid competition if we have an unlock code
//                $foundCompetitionResult = $this->GetValidCompetitionArray($userLanguage, $appVersionNum, $this->currentUserId);
//                if ($foundCompetitionResult)
//                   $result["ValidCompetition"] = $foundCompetitionResult;
            //}
//        }

//        date_default_timezone_set("UTC");
//        $currentTime =  date("Y-m-d H:i:s", time());

//        $token = md5(mt_rand());
//        $result["SessionToken"] = $token;

//        $deviceType = $this->getCleanValueFromArguments('deviceType');
//        $deviceModel = $this->getCleanValueFromArguments('deviceModel');
//        $deviceOS = $this->getCleanValueFromArguments('deviceOS');

//        # update session token in social server
//        $sql = "update \"User\" set (\"SessionToken\", \"LastTimeLoggedIn\", app_version_string, device_type, device_model, device_os)=('$token', '$currentTime', '$appVersionString', '$deviceType', '$deviceModel', '$deviceOS') where \"UserUID\"='$this->currentUserId'";
//        $this->db->exesql($sql);

//        return json_encode($result);
//    }

    function SchoologyAuthPreLogin()
    {
        include 'schoology_php_sdk/SchoologyApi.class.php';

        // Initialize the Schoology class
        $schoology = new SchoologyApi($this->schoology_consumer_key, $this->schoology_consumer_secret);
        
        try {
            $request_token_info = $schoology->api('oauth/request_token');

//ob_start();
//var_dump($request_token_info);
//$a=ob_get_contents();
//ob_end_clean();
//error_log($a);

            // Parse the query-string-formatted result
            $result_array = array();
            parse_str($request_token_info->result, $result_array);
    

            $oauth_request_token = $result_array['oauth_token'];
            $oauth_secret = $result_array['oauth_token_secret'];

            $this->db->exesql("insert into schoology_user (oauth_request_token, oauth_secret, expiry) values ('$oauth_request_token', '$oauth_secret', LOCALTIMESTAMP + interval '1 hour')");

            $result['result'] = 1;
            $result['request_token'] = $oauth_request_token;

        } catch (Exception $e) {
            die($this->JsonError("Schoology exception " . $e->getCode(), 'ServerMessageSchoologyException'));
        }

        return json_encode($result);
    }

    
    function SchoologyAuthPostLogin()
    {
        include 'schoology_php_sdk/SchoologyApi.class.php';

        $request_token = $this->getCleanValueFromArguments("oauth_token", true);
        $oauth_secret = $this->db->fetchValue("select oauth_secret from schoology_user where oauth_request_token = '$request_token'");

//        error_log('request_token "' . $request_token . '"' );
//        error_log('oauth_secret "' . $oauth_secret . '"');

        // Initialize the Schoology class
        $schoology = new SchoologyApi($this->schoology_consumer_key, $this->schoology_consumer_secret, '', $request_token, $oauth_secret);

        try {
            $access_token_info = $schoology->api('oauth/access_token');

//ob_start();
//var_dump($access_token_info);
//$a=ob_get_contents();
//ob_end_clean();
//error_log($a);

            // Parse the query-string-formatted result
            $result_array = array();
            parse_str($access_token_info->result, $result_array);


            $oauth_token = $result_array['oauth_token'];
            $oauth_secret = $result_array['oauth_token_secret'];


            // replace schoology api with one with new tokens
            $schoology = new SchoologyApi($this->schoology_consumer_key, $this->schoology_consumer_secret, '', $oauth_token, $oauth_secret);

            $web_session_info = $schoology->apiResult('app-user-info');
            $schoology_id = $web_session_info->api_uid;

//error_log('Schoology_id ' . $schoology_id);

            // insert or replace entry in schoology user table (http://stackoverflow.com/questions/1109061/insert-on-duplicate-update-in-postgresql)
            $this->db->exesql("update schoology_user set oauth_token='$oauth_token', oauth_secret='$oauth_secret', oauth_request_token='$request_token' where schoology_id = '$schoology_id'");
            $this->db->exesql("insert into schoology_user (schoology_id, oauth_token, oauth_secret, oauth_request_token) select $schoology_id as constant, '$oauth_token' as constant, '$oauth_secret' as constant, '$request_token' as constant where not exists (select 1 from schoology_user where schoology_id = $schoology_id)");
            $this->db->exesql("delete from schoology_user where schoology_id is null and oauth_request_token='$request_token'");

            $user_name = $this->db->fetchValue("select user_name from schoology_user where schoology_id=$schoology_id");

            if ($user_name == null)
            {
                $schoology_user_info = $schoology->apiResult("users/$schoology_id");
                $schoology_username = $schoology_user_info->name_display;
                $schoology_building = $schoology_user_info->building_id;


                // for now only newton uses this api
                $unlock_code = '389';

//                $course_info = $schoology->apiResult("courses?building_id=$schoology_building");

//ob_start();
//var_dump($course_info);
//$a=ob_get_contents();
//ob_end_clean();
//error_log($a);

//                $course_title = $course_info->title;

                $course_title = 'New Users';

                $category_id = $this->db->fetchValue("select \"CategoryUID\" from \"CodeCategories\" where \"CodeUID\" = $unlock_code and \"CategoryName\" ilike '$course_title'");

                if (!$category_id)
                {
                    $this->db->exesql("insert into \"CodeCategories\" (\"CategoryName\", \"CodeUID\") values ('$course_title', $unlock_code)");
                    $category_id = $this->db->fetchValue("select \"CategoryUID\" from \"CodeCategories\" where \"CodeUID\" = $unlock_code and \"CategoryName\" ilike '$course_title'");
                    //error_log("added category $category_id");
                }

                if ($this->db->fetchValue("select \"UserUID\" from \"User\" where \"UserName\" ilike '$schoology_username'") == null)
                {
                    $this->db->exesql("update schoology_user set user_uid=-1, user_name='$schoology_username', unlock_code_id=$unlock_code, code_category_id=$category_id where schoology_id = '$schoology_id'");
                }
                else
                {
                    while (true)
                    {
                        $modified_username = $schoology_username . mt_rand(0,9) . mt_rand(0,9);
                        if ($this->db->fetchValue("select \"UserUID\" from \"User\" where \"UserName\" ilike '$modified_username'") == null)
                        {
                            $this->db->exesql("update schoology_user set user_uid=-1, user_name='$modified_username', unlock_code_id=$unlock_code, code_category_id=$category_id where schoology_id = '$schoology_id'");
                            break;
                        }
                    }
                }
            }

        } catch (Exception $e) {

            $error_message = $e->getMessage();
            $this->db->exesql("update schoology_user set error='$error_message' where oauth_request_token='$request_token'");

            die($this->JsonError("Schoology exception " . $e->getCode(), 'ServerMessageSchoologyException'));
        }


//        $actual_link = "http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
//        $log = new Logger('api');
//        $log->pushHandler(new StreamHandler('/var/log/picto/testauth.log', Logger::INFO));
//        $log->addInfo($actual_link);
    }


    function LoginWithSchoology()
    {
        $request_token = $this->getCleanValueFromArguments("request_token", true);

        $user_uid = $this->db->fetchValue("select user_uid from schoology_user where oauth_request_token='$request_token'");
        $error = $this->db->fetchValue("select error from schoology_user where oauth_request_token='$request_token'");

        if ($user_uid === null || $error != null)
        {
            $this->db->exesql("update schoology_user set login_failures = login_failures + 1 where oauth_request_token='$request_token'");
            if ($this->db->fetchValue("select login_failures from schoology_user where oauth_request_token='$request_token'") > 30)
                $error = "Exceeded max login requests waiting for redirected request";

            $result["result"] = 0;
            $result["msg"] = "Schoology login failed";
            $result["msgKey"] = 'ServerMessageSchoologyTokenNotValid';
            if ($error != null)
                $result["schoology_error"] = $error;
        }
        else if ($user_uid == -1)
        {
            $result["result"] = 1;
            $result["user_uid"] = $user_uid;
            $result["user_name_suggestion"] = $this->db->fetchValue("select user_name from schoology_user where oauth_request_token='$request_token'");
        }
        else
        {
            $this->arguments["username"] = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\" = '$user_uid'");
            $this->arguments["token"] = 'hack';
            $password = $this->db->fetchValue("select \"Password\" from \"User\" where \"UserUID\" = '$user_uid'");
//error_log('password ' . $password);
            $this->arguments["password"] = md5('hack'.$password);
            return $this->LoginUser();
        }

        return json_encode($result);
    }

    function SchoologyCreateAccount()
    {
        $request_token = $this->getCleanValueFromArguments("request_token", true);
        $username = $this->getCleanValueFromArguments("username", true);

        $this->arguments['password'] = $request_token;

        // TODO: Fix case where username is not created for whatever reason (e.g. bad word filter)

        // create our user account
        $this->CreateAccountWithUsername();
        $token = 'hack';
        $this->arguments['token'] = $token;
        $this->arguments['password'] = md5($token.md5($request_token));
        $session_token = md5($request_token);
        $this->db->exesql("update \"User\" set \"SessionToken\"='$session_token' where \"UserName\" ilike '$username'");

        // set our user id in schoology table
        $user_uid = $this->db->fetchValue("select \"UserUID\" from \"User\" where \"UserName\" ilike '$username'");
        $this->db->exesql("update schoology_user set user_uid=$user_uid where oauth_request_token='$request_token'");

        // set unlock code and category in our user table
        $codeuid = $this->db->fetchValue("select unlock_code_id from schoology_user where oauth_request_token='$request_token'");
        $this->arguments['Code'] = $this->db->fetchValue("select \"Code\" from \"UnlockCodes\" where codeuid=$codeuid");
        $this->VerifyCode();

        $this->arguments['CategoryUID'] = $this->db->fetchValue("select code_category_id from schoology_user where oauth_request_token='$request_token'");
        $this->SetCategory();

        // return login info to the app
        return $this->LoginUser();
    }

    function GetUserNotifications()
    {
        $this->checkUser(true);

        $sql = "select * from notifications where (user_id is null or user_id = '$this->currentUserId') and id not in (select notification_id from notification_statuses where user_id = '$this->currentUserId' and status = 'closed')";
        $validNotifications = $this->db->sqlToArray($sql);
        if ($validNotifications)
        {
            $result["result"] = 1;
            $result["Notifications"] = $validNotifications;
        }
        else
            $result["result"] = 0;

        return json_encode($result);
    }

    private function GetValidCompetitionArray($userLanguage, $appVersionNum, $userID)
    {
        if ($appVersionNum > 2.5)
        {
            $sql = "select id, title, description, start_time, end_time, terms_and_conditions, language, email_subject, email_title, email_subject_extended, email_jury, email_tips, email_prize from competitions where language = '" .$userLanguage. "' and localtimestamp > start_time and localtimestamp < end_time";
            $competitionArray = $this->db->sqlToArray($sql);
            if ($competitionArray)
            {
                $competitionId = $competitionArray[0]["id"];
                $result["Competition"] = $competitionArray;

                // this is for the old app version that displays entries on login
                // get some submission design ids to pass back with this function
                $sql = "select design_id, description from competition_submissions where competition_id = $competitionId order by random() limit 3";
                $submissionsArray = $this->db->sqlToArray($sql);
                if ($submissionsArray)
                {
                    $result["Competition_Submissions"] = $submissionsArray;
                }

                // check if this user has a current entry
                $sql = "select id, design_id, description from competition_submissions where competition_id = $competitionId and design_id in (select \"DesignUID\" from \"Design\" where \"OwnerUID\" = '$userID')";
                $userSubmissionDetails = $this->db->sqlToArray($sql);
                if ($userSubmissionDetails)
                {
                    $result["CurrentUserSubmission"] = $userSubmissionDetails;
                }

                return $result;
            }
        }
    }

    function LogoutUser()
    {
        $this->checkUser(true);

        # clean session token in social server
        $arr["SessionToken"] = "";
        return $this->db->UpdateAndReturnJson("User", $arr, " WHERE \"UserUID\" = '$this->currentUserId' ");
    }

    function NotificationShownToUser()
    {
        $this->checkUser(true);
        $notification_id = $this->getCleanValueFromArguments("notification_id");

        $sql = "select id from notification_statuses where user_id = '$this->currentUserId' and notification_id = '$notification_id'";
        $notification_status_id = $this->db->fetchValue($sql);

        if ($notification_status_id)
        {
            // if we have an entry all we need to do is increment the times_shown count
            $sql = "update notification_statuses set times_shown = times_shown + 1 where id = '$notification_status_id'";
            $this->db->exesql($sql);
        }
        else
        {
            // if we don't have an entry we need to create one with its times_shown count at 1
            $sql = "insert into notification_statuses (user_id, notification_id, times_shown) values ('$this->currentUserId', '$notification_id', '1')";
            $this->db->exesql($sql);
        }
        $result["result"] = 1;
        return json_encode($result);
    }

    function CloseInAppNotification()
    {
        $this->checkUser(true);
        $notification_id = $this->getCleanValueFromArguments("notification_id");

        $sql = "select id from notification_statuses where user_id = '$this->currentUserId' and notification_id = '$notification_id'";
        $notification_status_id = $this->db->fetchValue($sql);

        $sql = "update notification_statuses set status = 'closed' where id = '$notification_status_id'";
        $this->db->exesql($sql);

        $result["result"] = 1;
        return json_encode($result);
    }

    function AddNotificationDeviceToken()
    {
        $this->checkUser(true);

        // mark as failed unless successfully set later
        $arr["result"] = 1;

        $deviceToken = $this->getCleanValueFromArguments('deviceToken');

        if ($deviceToken != "")
        {
            $sql = "insert into user_notification_device_tokens (user_uid, device_token) select '?my_Id?', '?device_token?' where not exists ( select id from user_notification_device_tokens where user_uid = '?my_Id?' and device_token = '?device_token?')";
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
            $sql = str_replace("?device_token?", $deviceToken, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
            //else
            //{
            //    $this->db->exesql("update \"User\" set \"Followers\"=\"Followers\" + 1 where \"UserUID\"='$UserUID'");
            //}
        }

        return json_encode($arr);


    }

    function SetMakerBotCode()
    {
        $this->checkUser(true);

        $code = $this->getCleanValueFromArguments('code', true);

        if ($code == '')
        {
            // clear code and username from account
            $sql = "update \"User\" set (makerbot_token, makerbot_username) = values('','') where \"UserUID\"='$this->currentUserId'";
            $arr['result'] = 1;
            $arr['makerbot_username'] = '';

            return json_encode($arr);
        }

        $accessUrl = 'https://www.thingiverse.com/login/oauth/access_token';
        
        $data = array('client_id' => 'f3059e0a11a8d384dc42', 'client_secret' => '2bf4a1f27693781ea03135161df0c9da', 'code' => $code);

        // use key 'http' even if you send the request to https://...
        $options = array(
            'http' => array(
                'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                'method'  => 'POST',
                'content' => http_build_query($data),
            ),
        );
        $context  = stream_context_create($options);
        $result = file_get_contents($accessUrl, false, $context);

        parse_str($result);

        $sql = "update \"User\" set makerbot_token ='$access_token' where \"UserUID\"='$this->currentUserId'";
        $this->db->exesql($sql);

        // get makerbot username
        $userDetailsJson = file_get_contents("https://api.thingiverse.com/users/me?access_token=".$access_token);
        error_log($userDetailsJson);
        $userDetails = @json_decode($userDetailsJson);
        $makerbotUsername = $userDetails->name;
        if ($makerbotUsername != '')
        {
            $sql = "update \"User\" set makerbot_username ='$makerbotUsername' where \"UserUID\"='$this->currentUserId'";
            $this->db->exesql($sql);

            $arr['result'] = 1;
            $arr['makerbot_username'] = $makerbotUsername;

            // add a design to the export queue to trigger sync without waiting for it to complete (bit of a hack, sorry)
            $designUID = $this->db->fetchValue("select \"DesignUID\" from \"Design\" where \"OwnerUID\"='$this->currentUserId' limit 1");
            if ($designUID)
                $this->InsertDesignIntoExportQueue($designUID);
        }
        else
        {
            $arr['result'] = 0;
        }

        return json_encode($arr);
    }

    function DeleteMEThings()
    {
        $this->DeleteMakerBotThings('2769');
    }

    function DeleteMakerBotThings($userUID)
    {
        // check which modules the user has unlocked
        $sql = "select \"UserName\", makerbot_token, makerbot_username, \"CanExportKeychain\", \"CanExportDoodler\", \"CanExportAvatar\", \"CanExportBlocker\", \"CanExportToyDesigner\", \"CanExportGears\" from \"User\" where \"UserUID\"='$userUID'";

        $result = $this->db->sqlToArray($sql);
        if (!$result)
        {
            return $this->JsonError("User cannot be found", 'ServerMessage1');
        }
        $userData = $result[0];

        $makerbotToken = $userData['makerbot_token'];
        if ($makerbotToken == null || $makerbotToken == '')
            return;

        $sql = "select \"DesignUID\", \"DisplayName\", makerbot_id, makerbot_stl_file_id, stl_date, makerbot_upload_date, \"Type\" from \"Design\" where \"OwnerUID\"='$userUID'";
        $designs = $this->db->sqlToArray($sql);

        if ($designs)
        {
            for ($i=0; $i < count($designs); $i++)
            {
                    if ($designs[$i]['makerbot_id'] == null || $designs[$i]['makerbot_id'] == 0)
                    {
                        echo 'no makerbot id for ' . $designs[$i]['DesignUID'] . "\r\n";
                    }
                    else
                    {
                        $makerbot_id = $designs[$i]['makerbot_id'];
                        $makerbot_stl_file_id = $designs[$i]['makerbot_stl_file_id'];
                            
                        // remove old thing file
                        if ($designs[$i]['makerbot_stl_file_id'] != null && $designs[$i]['makerbot_stl_file_id'] != 0)
                            $this->DeleteMakerBotFile($makerbot_id, $designs[$i]['makerbot_stl_file_id'], $makerbotToken);

                        $this->DeleteMakerBotThing($makerbot_id, $makerbotToken);
                    }
             }
        }
    }

    function SyncToMakerBot($userUID)
    {
        // check which modules the user has unlocked
        $sql = "select \"UserName\", makerbot_token, makerbot_username, \"CanExportKeychain\", \"CanExportDoodler\", \"CanExportAvatar\", \"CanExportBlocker\", \"CanExportToyDesigner\", \"CanExportGears\" from \"User\" where \"UserUID\"='$userUID'";

        $result = $this->db->sqlToArray($sql);
        if (!$result)
        {
            return $this->JsonError("User cannot be found", 'ServerMessage1');
        }
        $userData = $result[0];

        $makerbotToken = $userData['makerbot_token'];
        if ($makerbotToken == null || $makerbotToken == '')
            return;

        $sql = "select \"DesignUID\" from \"Like\" where \"UserUID\"=$userUID";

        $likedDesigns = $this->db->sqlToArray($sql);
        $likedCondition = '';
        if ($likedDesigns)
        {
            for ($i=0; $i < count($likedDesigns); $i++)
            {
                $likedIdArray[] = "'".$likedDesigns[$i]["DesignUID"]."'";
            }
       
            $likedIdString = implode(',', $likedIdArray);
            if ($likedIdString != "")
            {
                $likedCondition = " or \"DesignUID\" in ($likedIdString)";
            }
        }

        $sql = "select \"DesignUID\", \"DisplayName\", makerbot_id, makerbot_stl_file_id, stl_date, makerbot_upload_date, \"Type\" from \"Design\" where \"OwnerUID\"='?my_Id?'" . $likedCondition;
        $sql = str_replace("?my_Id?", $userUID, $sql);
        $designs = $this->db->sqlToArray($sql);

        if ($designs)
        {
            for ($i=0; $i < count($designs); $i++)
            {
                if (($designs[$i]['Type'] <= 1 && $userData['CanExportKeychain'] == 't') || ($designs[$i]['Type'] == 2 && $userData['CanExportDoodler'] == 't') || ($designs[$i]['Type'] == 3 && $userData['CanExportAvatar'] == 't') || ($designs[$i]['Type'] == 4 && $userData['CanExportBlocker'] == 't') || ($designs[$i]['Type'] == 8 && $userData['CanExportToyDesigner'] == 't') || ($designs[$i]['Type'] == 9 && $userData['CanExportGears'] == 't'))
                {
                    if ($designs[$i]['makerbot_id'] == null || $designs[$i]['makerbot_id'] == 0)
                    {
                        // create thing
                        $thingName = $designs[$i]['DisplayName'];
                        if ($thingName == "")
                            $thingName = 'untitled';

                        $makerbot_id = $this->CreateMakerBotThing($thingName, $makerbotToken);
                        $makerbot_stl_file_id = 0;
                    }
                    else
                    {
                        $makerbot_id = $designs[$i]['makerbot_id'];
                        $makerbot_stl_file_id = $designs[$i]['makerbot_stl_file_id'];

                        if ($designs[$i]['stl_date'] > $designs[$i]['makerbot_upload_date'])
                        {
                            // remove old thing file
                            if ($designs[$i]['makerbot_stl_file_id'] != null && $designs[$i]['makerbot_stl_file_id'] != 0)
                                $this->DeleteMakerBotFile($makerbot_id, $designs[$i]['makerbot_stl_file_id'], $makerbotToken);
                            $makerbot_stl_file_id = 0;
                        }
                    }

                    $designUID = $designs[$i]['DesignUID'];
                    $stl_date = $designs[$i]['stl_date'];

                    // set a default stl date if current stl predates stl date storing code
                    if ($stl_date == null || $stl_date == '')
                        $stl_date = '2014-01-01';

                    if ($makerbot_stl_file_id == 0)
                    {
                        $fileName = $designUID . '.stl';
                        $pathName = 'stl/' . substr($fileName, 0, 2);
                        $fileRelativePath = $pathName . '/' . $fileName;
                        $filenameToShow = $userData['UserName'];
                        if ($designs[$i]['DisplayName'] != "")
                            $filenameToShow .= '_' . $designs[$i]['DisplayName'];
                        $filenameToShow = preg_replace("/[^A-Za-z0-9 ]/", '', $filenameToShow); 
                        $filenameToShow .= '.stl';

                        $makerbot_stl_file_id = $this->UploadFileToMakerBot($makerbot_id, $pathName . '/' . $fileName, $filenameToShow, $makerbotToken);
                    }

                    $this->db->exesql("update \"Design\" set makerbot_id=$makerbot_id, makerbot_stl_file_id=$makerbot_stl_file_id, makerbot_upload_date='$stl_date' where \"DesignUID\"='$designUID'");

                    error_log("Set makerbot_id to $makerbot_id for $designUID");
                }
            }
        }
    }

    function CreateMakerBotThing($thingName, $token)
    {
        $thingiverse = new Thingiverse($token);

        $response = $thingiverse->createThing($thingName, 'cc', 'Art');

        if (!isset($thingiverse->response_data->id))
        {
            error_log('Thingiverse response: ' . $response . ' error ' . $thingiverse->last_response_error);
            return 0;
        }

        $makerbot_id = $thingiverse->response_data->id;

        // get Makers Empire collection and add the thing to it
        $thingiverse->getCollections('makers-empire');

        error_log('collection id : ' . $thingiverse->response_data->id);        

        $response = $thingiverse->addCollectionThing($thingiverse->response_data->id, $makerbot_id);

        error_log('add thing response ' . $response);

        return $makerbot_id;
    }

    function UploadFileToMakerBot($makerbot_id, $path, $filename, $token)
    {
        $thingiverse = new Thingiverse($token);

        $response = $thingiverse->uploadThingFile($makerbot_id, $filename);

        $params = (array)$thingiverse->response_data->fields;
        $destination = $thingiverse->response_data->action;

        $eol = "\r\n";
        $data = '';

        $mime_boundary='---------------------------66289253989742337765937765';//.md5(time());

        while (($param = current($params)) !== False)
        {
            $data .= '--' . $mime_boundary . $eol;
            $data .= 'Content-Disposition: form-data; name="'.key($params).'"' . $eol . $eol;
            $data .= $param . $eol;

            next($params);
        }

        $data .= '--' . $mime_boundary . $eol;
        $data .= 'Content-Disposition: form-data; name="file"; filename="$filename"' . $eol;
        $data .= 'Content-Type: application/sla' . $eol . $eol;

        $data .=  file_get_contents($path) . $eol;

        $data .= "--" . $mime_boundary . '--' . $eol . $eol; // finish with two eol's!!

        $header = '';
        $header .= 'Content-Type: multipart/form-data; boundary=' . $mime_boundary . $eol ;
        $header .= 'Content-Length: ' . strlen($data) . $eol . $eol;
        $params = array('http' => array(
                          'method' => 'POST',
                          //'ignore_errors' => true,
                          'header' => $header,
                          'content' => $data,
                          'follow_location' => false  // doesn't seem to stop the redirection
                       ));

        # Enable Error Reporting and Display:
        //error_reporting(~0);
        //ini_set('display_errors', 1);

        $ctx = stream_context_create($params);

        $response = file_get_contents($destination, false, $ctx);

        // find the redirect URL in the response header and call it again with Authorization token in header
        for ($i=0; $i < count($http_response_header); $i++)
        {
            error_log('Response headers: ' . $http_response_header[$i]);

            $pos = strpos($http_response_header[$i], 'https://api.thingiverse');
            if ($pos !== FALSE)
            {
                $destination = substr($http_response_header[$i], $pos);

                $header = 'Authorization: Bearer ' . $token . $eol . $eol;

                $params = array('http' => array(
                          'method' => 'POST',
                          'ignore_errors' => true,
                          'header' => $header,
                          //'content' => $data,
                          //'follow_location' => false
                       ));

                $ctx = stream_context_create($params);

                $responseJson = file_get_contents($destination, false, $ctx);
                $response = @json_decode($responseJson);

                if (isset($response->id))
                   return $response->id;
            }
        }

        return 0;
    }

    function DeleteMakerBotFile($thingId, $fileId, $token)
	{
        $thingiverse = new Thingiverse($token);

        $response = $thingiverse->deleteThingFile($thingId, $fileId);

		return $response;
	}

    function DeleteMakerBotThing($thingId, $token)
    {
        $thingiverse = new Thingiverse($token);
        $response = $thingiverse->deleteThing($thingId);
        return $response;
    }

    function SetUserInfo()
    {
        $this->checkUser(true);

        $option = $this->getCleanValueFromArguments('option');

        if ($option == 1 || $option == 2)
        {
            $password = $this->getCleanValueFromArguments('newPassword');
            if (strlen($password) > 1)
            {
                $token = $this->getCleanValueFromArguments('token', true);
                $sql = "update \"User\" set \"ResetPasswordToken\"='$token', \"TokenExpireDate\"= current_date+interval '24 hours' where \"UserUID\"='$this->currentUserId'";
                $this->db->exesql($sql);
                $ret = $this->UpdatePassword($password);

                if ($ret != 1)
                {
                    if ($ret == -1)
                    {
                        $result["msg"] = "Your username or your token is not valid";
                        $result["msgKey"] = 'ServerMessage20';
                    }
                    else if ($ret == -2)
                    {
                        $result["msg"] = "Your email or your token is not valid";
                        $result["msgKey"] = 'ServerMessage17';
                    }
                    else if ($ret == -3)
                    {
                        $result["msg"] = "Your token has expired";
                        $result["msgKey"] = 'ServerMessage21';
                    }
                    else
                    {
                        $result["msg"] = "Unknown error has occurred while setting the password.";
                        $result["msgKey"] = 'ServerMessage68';
                    }

                    $result["result"] = 0;

                    return json_encode($result);
                }
            }

            $sql = "";
            if ($option == 1) // student info, set at the end of registration process
            {
                $categoryID = $this->getCleanValueFromArguments('CategoryUID');
                $userLanguage = $this->getCleanValueFromArguments("language");
                if ($categoryID == '')
                {
                    $categoryID = 0;
                }

                $sql = "update \"User\" set \"CodeCategory\" = '?category?', \"DisplayName\" = '?fullName?' where \"UserUID\" = '$this->currentUserId'";
                $sql = str_replace("?category?", $categoryID, $sql);
                $sql = str_replace("?fullName?", $this->getCleanValueFromArguments('DisplayName'), $sql);

                $result["CategoryUID"] = $categoryID;

                if ($categoryID != 0)
                {
                    $policyArray = $this->db->fetchArray("select a.\"SharingPolicy\" as \"ClassSharingPolicy\", a.\"ViewingPolicy\" as \"ClassViewingPolicy\", a.\"MakerBotIntegration\" as \"ClassMakerBotIntegration\", b.\"SharingPolicy\" as \"SchoolSharingPolicy\", b.\"ViewingPolicy\" as \"SchoolViewingPolicy\", b.\"MakerBotIntegration\" as \"SchoolMakerBotIntegration\" from \"CodeCategories\" a, \"UnlockCodes\" b where a.\"CategoryUID\" = '".$categoryID."' and b.codeuid = a.\"CodeUID\"");

                    if ($policyArray)
                    {
                        $result["SharingPolicy"] = $policyArray["ClassSharingPolicy"] != $this->scopeDefault ? $policyArray["ClassSharingPolicy"] : $policyArray["SchoolSharingPolicy"];
                        $result["ViewingPolicy"] = $policyArray["ClassViewingPolicy"] != $this->scopeDefault ? $policyArray["ClassViewingPolicy"] : $policyArray["SchoolViewingPolicy"];
                        $result["MakerBotIntegration"] = $policyArray["ClassMakerBotIntegration"] != "-1" ? $policyArray["ClassMakerBotIntegration"] : $policyArray["SchoolMakerBotIntegration"];
                    }
                    else
                    {
                        $result["SharingPolicy"] = $this->scopeClass;
                        $result["ViewingPolicy"] = $this->scopeClass;
                        $result["MakerBotIntegration"] = "0";
                    }
                }
                else
                {
                    $schoolCode = $this->db->fetchValue("select \"UnlockCode\" from \"User\" where \"UserUID\" = $this->currentUserId");
                    if ($schoolCode && $schoolCode != 0)
                    {
                        $policyArray = $this->db->fetchArray("select \"SharingPolicy\", \"ViewingPolicy\", \"MakerBotIntegration\" from \"UnlockCodes\" where codeuid = $schoolCode");
                    }
                    else
                        $policyArray = false;

                    if ($policyArray)
                    {
                        $result["SharingPolicy"] = $policyArray["SharingPolicy"];
                        $result["ViewingPolicy"] = $policyArray["ViewingPolicy"];
                        $result["MakerBotIntegration"] = $policyArray["MakerBotIntegration"];
                    }
                    else
                    {
                        $result["SharingPolicy"] = $this->scopeWorldwide;
                        $result["ViewingPolicy"] = $this->scopeWorldwide;
                        $result["MakerBotIntegration"] = "1";
                    }
                }

                if ($result["SharingPolicy"] == $this->scopeWorldwide && $result["ViewingPolicy"] == $this->scopeWorldwide)
                {

                    $appVersionString = $this->getCleanValueFromArguments("version");
                    if ($appVersionString != null)
                    {
                        $vPos = strpos($appVersionString, 'v');
                        $appVersionNum = substr($appVersionString, $vPos+1);

                        $validCompetitionArray = $this->GetValidCompetitionArray($userLanguage, $appVersionNum, $this->currentUserId);
                        if ($validCompetitionArray)
                            $result["ValidCompetition"] = $validCompetitionArray;
                    }
                }

                $this->db->exesql("update \"Design\" set \"SharingPolicy\" = " . $result["SharingPolicy"] . " where \"OwnerUID\" = $this->currentUserId");
            }
            else if ($option == 2) // non-student info, set at the end of registration process
            {
                $sql = "update \"User\" set \"Email\" = '?email?' where \"UserUID\" = '$this->currentUserId'";
                $sql = str_replace("?email?", $this->getCleanValueFromArguments('Email'), $sql);
            }

            $queryResult = $this->db->exesql($sql);
            $querySucceeded = pg_affected_rows($queryResult) > 0;
            if ($querySucceeded)
            {
                $result["result"] = 1;
            }
            else
            {
                $result["result"] = 0;
                $result["msg"] = "Unknown error occurred while updating user data.";
                $result["msgKey"] = 'ServerMessage63';
            }
        }
        else if ($option == 3) // profile settings
        {
            $uDescription = $this->getCleanValueFromArguments("Description");
            $uLocation = $this->getCleanValueFromArguments("Location");

            if ($this->ContainsBadWord($uDescription, "user id - $this->currentUserId entered into profile description area", "update \"User\" set \"Description\" = ''$uDescription'' where \"UserUID\" = ''$this->currentUserId''"))
            {
                $result["result"] = 1;
                $result["msg"] = "description contains a restricted word and has been ignored";
                return json_encode($result);
            }
            else if ($this->ContainsBadWord($uLocation, "user id - $this->currentUserId entered into profile location area", "update \"User\" set \"Location\" = ''$uLocation'' where \"UserUID\" = ''$this->currentUserId''"))
            {
                $result["result"] = 1;
                $result["msg"] = "location contains a restricted word and has been ignored";
                return json_encode($result);
            }

            $sql = "update \"User\" set \"Description\" = '?description?', \"Location\" = '?location?' where \"UserUID\" = '$this->currentUserId'";
            $sql = str_replace("?description?", $this->getCleanValueFromArguments('Description'), $sql);
            $sql = str_replace("?location?", $this->getCleanValueFromArguments('Location'), $sql);

            $queryResult = $this->db->exesql($sql);
            $querySucceeded = pg_affected_rows($queryResult) > 0;
            if ($querySucceeded)
            {
                $result["result"] = 1;
            }
            else
            {
                $result["result"] = 0;
                $result["msg"] = "Unknown error occurred while updating user data.";
                $result["msgKey"] = 'ServerMessage63';
            }
        }
        else if ($option == 4) // disable competition by competition id
        {
            $competition_id = $this->getCleanValueFromArguments("competition_id");
            $sql = "update \"User\" set disabled_competition_id = $competition_id where \"UserUID\" = '$this->currentUserId'";
            $queryResult = $this->db->exesql($sql);
            $querySuceeded = pg_affected_rows($queryResult) > 0;
            if ($querySucceeded)
            {
                $result["result"] = 1;
            }
            else
            {
                $result["result"] = 0;
                $result["msg"] = "Unknown error occurred while updating user data.";
                $result["msgKey"] = 'ServerMessage63';
            }
        }
        else // old client code, used for updating info via settings panel
        {
            $newUsername = strtolower($this->getCleanValueFromArguments('DisplayName'));
            $sql = "select count(*) from \"User\" where (\"UserName\") = '?username?' and \"UserUID\" != '$this->currentUserId'";
            $sql = str_replace("?username?", $newUsername, $sql);
            $count = $this->db->fetchValue($sql);

            if ($count == 0)
            {
                $arr["DisplayName"] = $newUsername;
                $arr["Description"] = $this->getCleanValueFromArguments('Description');
                $arr["Location"] = $this->getCleanValueFromArguments('Location');

                return $this->db->UpdateAndReturnJson("User", $arr, " WHERE \"UserUID\" = '$this->currentUserId' ");
            }
            else
            {
                $result["msg"] = "Selected name is already taken. Please try with another one.";
                $result["msgKey"] = 'ServerMessage69';
                $result["result"] = 0;
            }
        }

        return json_encode($result);
    }

    function GetUserInfo()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $UserUID = $this->getCleanValueFromArguments('UserUID', true);

        $sql = "select \"UserName\", \"PictureUrl\", \"Description\", \"Location\", \"AccountCreationDate\" from \"User\" where \"UserUID\" = '?user_Id?'";
        $sql = str_replace("?user_Id?", $UserUID, $sql);

        $arr = $this->db->fetchArray($sql);
        if (!$arr)
        {
            $arr["msg"] = "User was not found in the database";
            $arr["msgKey"] = 'ServerMessage67';
            $arr["result"] = 0;
        }
        else
        {
            $sql = "select \"Likes\", \"ViewCount\" from \"Design\" where \"OwnerUID\"='?user_Id?' and \"IsShared\"='t'";
            $sql = str_replace("?user_Id?", $UserUID, $sql);
            $designs = $this->db->sqlToArray($sql);

            $arr["Followers"] = $this->db->fetchValue("select count(\"FollowerUID\") from \"Follow\" where \"FollowedUserUID\"='$UserUID'");
            $arr["IsFollowedByMe"] = $isUserLoggedIn ? $this->IsUserFollowedByMe($UserUID) : '0';

            if ($designs)
            {
                $views = 0;
                $likes = 0;
                for ($i=0; $i < count($designs); $i++)
                {
                    $views += $designs[$i]['ViewCount'];
                    $likes += $designs[$i]['Likes'];
                }

                $arr["Designs"] = count($designs);
                $arr["Views"] = $views;
                $arr["Likes"] = $likes;
            }
            else
            {
                $arr["Designs"] = 0;
            }

            $arr["result"] = 1;
        }

        $arr["UserUID"] = $UserUID;

        return json_encode($arr);
    }

    function GetUserName()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $UserUID = $this->getCleanValueFromArguments('UserUID', true);

        $sql = "select \"UserName\" from \"User\" where \"UserUID\" = '?user_Id?'";
        $sql = str_replace("?user_Id?", $UserUID, $sql);

        $name = $this->db->fetchValue($sql);

        $arr["UserUID"] = $UserUID;
        $arr["UserName"] = $name;
        $arr["ItemType"] = $this->getCleanValueFromArguments('ItemType');
        $arr["ItemUID"] = $this->getCleanValueFromArguments('ItemUID');
        $arr["result"] = 1;

        return json_encode($arr);
    }

    function FollowUser()
    {
        $this->checkUser(true);

        $UserUID = $this->getCleanValueFromArguments('UserUID', true);
        $arr["UserUID"] = $UserUID;

        // don't do anything if the user doesn't exist
        $sql = "select count(\"UserUID\") as final_count from \"User\" where \"UserUID\"='?user_Id?'";
        $sql = str_replace("?user_Id?", $UserUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["msg"] = "User was not found in the database";
            $arr["msgKey"] = 'ServerMessage67';
            $arr["result"] = 0;

            return json_encode($arr);
        }

        $arr["result"] = 1;

        if ($this->IsUserFollowedByMe($UserUID) == 0)
        {
            $sql = "insert into \"Follow\" (\"FollowedUserUID\", \"FollowerUID\") values ('?user_Id?', '?my_Id?')";
            $sql = str_replace("?user_Id?", $UserUID, $sql);
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
            //else
            //{
            //    $this->db->exesql("update \"User\" set \"Followers\"=\"Followers\" + 1 where \"UserUID\"='$UserUID'");
            //}
        }

        return json_encode($arr);
    }

    function UnfollowUser()
    {
        $this->checkUser(true);

        $UserUID = $this->getCleanValueFromArguments('UserUID', true);

        $arr["UserUID"] = $UserUID;
        $arr["result"] = 1;

        $sql = "select count(\"UserUID\") as final_count from \"User\" where \"UserUID\"='?user_Id?'";
        $sql = str_replace("?user_Id?", $UserUID, $sql);
        $count = $this->db->fetchValue($sql);
        if ($count > 0)
        {
            $sql = "delete from \"Follow\" where \"FollowedUserUID\"='?user_Id?' and \"FollowerUID\"='?my_Id?'";
            $sql = str_replace("?user_Id?", $UserUID, $sql);
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
            //else
            //{
            //    $this->db->exesql("update \"User\" set \"Followers\"=\"Followers\" - 1 where \"UserUID\"='$UserUID'");
            //}
        }

        return json_encode($arr);
    }


    function GetPopularTags()
    {
        $limit = $this->getCleanValueFromArguments('Limit');
        
        if ($limit != '')
        {
            $sql = "select \"TagText\" from \"DesignTag\" group by \"TagText\" order by count(\"DesignUID\") desc limit ".$limit." offset 0";
        }
        else
        {
            $sql = "select \"TagText\" from \"DesignTag\" group by \"TagText\" order by count(\"DesignUID\") desc";
        }

        $rs = $this->db->exesql($sql);
        $tags = array();
        while($line = pg_fetch_array($rs))
        {
            $tags[] = $line["TagText"];
        }
        
        $resultArray["tags"] = implode(',', $tags);
        $resultArray["result"] = 1;
        
        return json_encode($resultArray);
    }

    function GetBuyOptions()
    {
        $prices = $this->db->sqlToArray("select * from \"Prices\" order by \"PriceUID\" asc");

        if ($prices)
        {
            for ($i=0; $i < count($prices); $i++)
            {
                $priceItem = $prices[$i];
                $arrayItem = array(
                    "id"   => (int)$priceItem['PriceUID'],
                    "name" => $priceItem['Name'],
                    "price" => (int)$priceItem['Price'],
                );
                $resultArray["prices"][$priceItem['Category']][] = $arrayItem;
            }
            $resultArray["result"] = 1;
        }
        else
        {
            $resultArray["result"] = 0;
        }

        return json_encode($resultArray);
    }

    function GetMaterialsForDesign()
    {
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

	$materials = $this->db->sqlToArray("select * from material");

	if ($materials)
	{
	    for ($i=0; $i < count($materials); $i++)
	    {
	        $materialItem = $materials[$i];
	        $materialPrice = $this->db->sqlToArray("select price from design_prices where \"DesignUID\"='".$DesignUID."' and material_uid=".$materialItem['material_uid']);

	        $arrayItem = array(
	                "price" => isset($materialPrice[0]) ? $materialPrice[0]['price'] : '0',
	            "name" => $materialItem['name'],
	            "picture_url" => $materialItem['picture_url'],
	            "colour" => $materialItem['colour'],
	        );

	        $resultArray["prices"][$materialItem['material_uid']][] = $arrayItem;
	    }
	    $resultArray["result"] = 1;
	}
	else
	{
	    $resultArray["result"] = 0;
	}

//	  $prices = $this->db->sqlToArray("select * from design_prices where \"DesignUID\"='".$DesignUID."'");

//        if ($prices)
//        {
//            for ($i=0; $i < count($prices); $i++)
//            {
//                $priceItem = $prices[$i];

//                $materials = $this->db->sqlToArray("select * from material where material_uid=".$priceItem['material_uid']);

//                if ($materials)
//                {
//                    $arrayItem = array(
//                        "price" => $priceItem['price'],
//                        "name" => $materials[0]['name'],
//                        "picture_url" => $materials[0]['picture_url'],
//                        "colour" => $materials[0]['colour'],
//                    );

//                    $resultArray["prices"][$materials[0]['material_uid']][] = $arrayItem;
//                }
//            }
//            $resultArray["result"] = 1;
//        }
//        else
//        {
//            $resultArray["result"] = 0;
//        }

        return json_encode($resultArray);
    }

    function GetDeliveryPrice()
    {
        $country = $this->getCleanValueFromArguments('country', true);

	$resultArray["price"] = $this->db->sqlToArray("select price_cents from delivery_prices where country = '".$country."'" );
        
        if (isset($resultArray["price"]))
            $resultArray["result"] = 1;
        else
            $resultArray["result"] = 0;

        return json_encode($resultArray);
    }

    private function IsDesignOwnedByMe($designID)
    {
        $sql = "select count(*) from \"Design\" where \"DesignUID\"='?design_Id?' and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?design_Id?", $designID, $sql);

        return $this->db->fetchValue($sql);
    }

    private function IsDesignLikedByMe($designID)
    {
        $sql = "select count(*) from \"Like\" where \"DesignUID\"='?design_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?design_Id?", $designID, $sql);

        return $this->db->fetchValue($sql);
    }

    private function IsDesignFavoritedByMe($designID)
    {
        $sql = "select count(*) from \"Favorite\" where \"DesignUID\"='?design_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?design_Id?", $designID, $sql);

        return $this->db->fetchValue($sql);
    }

    private function IsUserFollowedByMe($userID)
    {
        $sql = "select count(*) from \"Follow\" where \"FollowedUserUID\"='?user_Id?' and \"FollowerUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?user_Id?", $userID, $sql);

        return $this->db->fetchValue($sql);
    }

    private function IsTextureInDrawer($textureID)
    {
        $sql = "select count(*) from \"TextureDrawer\" where \"TextureUID\"='?texture_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?texture_Id?", $textureID, $sql);

        return $this->db->fetchValue($sql);
    }

    private function IsVideoInDrawer($videoID)
    {
        $sql = "select count(*) from \"VideoDrawer\" where \"VideoUID\"='?video_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?video_Id?", $videoID, $sql);

        return $this->db->fetchValue($sql);
    }

    private function IsGroupInDrawer($groupID)
    {
        $sql = "select count(*) from \"GroupDrawer\" where \"GroupUID\"='?group_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?group_Id?", $groupID, $sql);

        return $this->db->fetchValue($sql);
    }

    private function IsGroupATemplate($groupID)
    {
        $sql = "select count(*) from \"GroupTemplates\" where \"GroupUID\"='?group_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?group_Id?", $groupID, $sql);

        return $this->db->fetchValue($sql);
    }


    private function IsMeshInDrawer($meshID)
    {
        // shouldn't check against WasRemoved flag
        $sql = "select count(*) from \"MeshDrawer\" where \"MeshUID\"='?mesh_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?mesh_Id?", $meshID, $sql);

        return $this->db->fetchValue($sql);
    }

    private function IsMeshInToyDesignerDrawer($meshID)
    {
        $sql = "select count(*) from \"MeshDrawerToyDesigner\" where \"MeshUID\"='?mesh_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?mesh_Id?", $meshID, $sql);

        return $this->db->fetchValue($sql);
    }

    private function IsMeshATemplate($meshID)
    {
        $sql = "select count(*) from \"MeshTemplates\" where \"MeshUID\"='?mesh_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?mesh_Id?", $meshID, $sql);

        return $this->db->fetchValue($sql);
    }


    private function MyCommentsRate($commentID)
    {
        $sql = "select \"Rate\" from \"CommentRating\" where \"CommentUID\"='?comment_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?comment_Id?", $commentID, $sql);

        $ret = $this->db->fetchValue($sql);
        return $ret ? $ret : '0';
    }

    private function GetDesignPhotos($designID, $limit = 6, $photosToSkip = '')
    {
        $isOwnedByMe = $this->IsDesignOwnedByMe($designID) > 0;
        $returnNotAccepted = $isOwnedByMe ? "" : " and (\"IsAccepted\" = 't' or \"UserUID\" = '$this->currentUserId')";

        $sql = "select \"DesignPhotoUID\", \"UserUID\", \"PhotoUrl\", \"ThumbnailUrl\", \"IsAccepted\" from \"DesignPhotos\" where \"DesignUID\"='?design_Id?'" . $photosToSkip . $returnNotAccepted . " order by \"DesignPhotoUID\" asc limit $limit";
        $sql = str_replace("?design_Id?", $designID, $sql);

        $result = $this->db->sqlToArray($sql);
        return $result;
    }

    private function GetDesignTags($designID, $tagDatas)
    {
        if ($tagDatas == "true")
        {
            $sql = "select user_id, \"TagText\" from \"DesignTag\" where \"DesignUID\"='?design_Id?'";
            $sql = str_replace("?design_Id?", $designID, $sql);
            $result = $this->db->sqlToArray($sql);
            return $result ? $result : null;
        }
        else
        {
            $sql = "select \"TagText\" from \"DesignTag\" where \"DesignUID\"='?design_Id?'";
            $sql = str_replace("?design_Id?", $designID, $sql);
            return $this->GetTagsStringForQuery($sql);
        }
    }

    private function GetMeshTags($meshID, $tagDatas)
    {
        if ($tagDatas == "true")
        {
            $sql = "select user_id, \"TagText\" from \"MeshTag\" where \"MeshUID\" = '$meshID'";
            $result = $this->db->sqlToArray($sql);
            return $result ? $result : null;
        }
        else
        {
            $sql = "select \"TagText\" from \"MeshTag\" where \"MeshUID\"='?mesh_Id?'";
            $sql = str_replace("?mesh_Id?", $meshID, $sql);
            return $this->GetTagsStringForQuery($sql);
        }
    }

    private function GetGroupTags($groupID)
    {
        $sql = "select \"TagText\" from \"GroupTag\" where \"GroupUID\"='?group_Id?'";
        $sql = str_replace("?group_Id?", $groupID, $sql);

        return $this->GetTagsStringForQuery($sql);
    }

    private function GetVideoTags($videoID)
    {
        $sql = "select \"TagText\" from \"VideoTag\" where \"VideoUID\"='?video_Id?'";
        $sql = str_replace("?video_Id?", $videoID, $sql);

        return $this->GetTagsStringForQuery($sql);
    }

    private function GetTextureTags($textureID)
    {
        $sql = "select \"TagText\" from \"TextureTag\" where \"TextureUID\"='?texture_Id?'";
        $sql = str_replace("?texture_Id?", $textureID, $sql);

        return $this->GetTagsStringForQuery($sql);
    }

    private function GetTagsStringForQuery($sql)
    {
        $result = $this->db->exesql($sql);
        $tags = array();
        while($line = pg_fetch_array($result))
        {
            $tags[] = $line["TagText"];
        }

        return implode(',', $tags);
    }

    private function AddSingleTagToLevel($tagText, $levelId, $isDesignShared, $user_id = -1)
    {
        $tagText = strtolower(trim($tagText));
        $sql = "select count(\"DesignUID\") as current_count from \"DesignTag\" where \"DesignUID\"='?level_Id?' and \"TagText\"='?tag?'";
        $sql = str_replace("?level_Id?", $levelId, $sql);
        $sql = str_replace("?tag?", $tagText, $sql);
        $count = $this->db->fetchValue($sql);

        if ($count == 0)
        {
            $sql = "insert into \"DesignTag\" (\"DesignUID\", \"TagText\", user_id) values ('?design_Id?', '?tag?', $user_id)";
            $sql = str_replace("?design_Id?", $levelId, $sql);
            $sql = str_replace("?tag?", $tagText, $sql);
            $this->db->exesql($sql);
        }
    }

    private function AddSingleTagToTexture($tagText, $textureId)
    {
        $tagText = strtolower(trim($tagText));
        $sql = "select count(\"TextureUID\") as current_count from \"TextureTag\" where \"TextureUID\"='?texture_Id?' and \"TagText\"='?tag?'";
        $sql = str_replace("?texture_Id?", $textureId, $sql);
        $sql = str_replace("?tag?", $tagText, $sql);
        $count = $this->db->fetchValue($sql);

        if ($count == 0)
        {
            $sql = "insert into \"TextureTag\" (\"TextureUID\", \"TagText\") values ('?texture_Id?', '?tag?')";
            $sql = str_replace("?texture_Id?", $textureId, $sql);
            $sql = str_replace("?tag?", $tagText, $sql);
            $this->db->exesql($sql);
        }
    }

    private function AddSingleTagToMesh($tagText, $meshId, $user_id = -1)
    {
        $tagText = strtolower(trim($tagText));
        $sql = "select count(\"MeshUID\") as current_count from \"MeshTag\" where \"MeshUID\"='?mesh_Id?' and \"TagText\"='?tag?'";
        $sql = str_replace("?mesh_Id?", $meshId, $sql);
        $sql = str_replace("?tag?", $tagText, $sql);
        $count = $this->db->fetchValue($sql);

        if ($count == 0)
        {
            $sql = "insert into \"MeshTag\" (\"MeshUID\", \"TagText\", user_id) values ('?mesh_Id?', '?tag?', $user_id)";
            $sql = str_replace("?mesh_Id?", $meshId, $sql);
            $sql = str_replace("?tag?", $tagText, $sql);
            $this->db->exesql($sql);
        }
    }

    private function AddSingleTagToGroup($tagText, $groupId)
    {
        $tagText = strtolower(trim($tagText));
        $sql = "select count(\"GroupUID\") as current_count from \"GroupTag\" where \"GroupUID\"='?group_Id?' and \"TagText\"='?tag?'";
        $sql = str_replace("?group_Id?", $groupId, $sql);
        $sql = str_replace("?tag?", $tagText, $sql);
        $count = $this->db->fetchValue($sql);

        if ($count == 0)
        {
            $sql = "insert into \"GroupTag\" (\"GroupUID\", \"TagText\") values ('?group_Id?', '?tag?')";
            $sql = str_replace("?group_Id?", $groupId, $sql);
            $sql = str_replace("?tag?", $tagText, $sql);
            $this->db->exesql($sql);
        }
    }

    private function AddSingleTagToVideo($tagText, $videoId)
    {
        $tagText = strtolower(trim($tagText));
        $sql = "select count(\"VideoUID\") as current_count from \"VideoTag\" where \"VideoUID\"='?video_Id?' and \"TagText\"='?tag?'";
        $sql = str_replace("?video_Id?", $videoId, $sql);
        $sql = str_replace("?tag?", $tagText, $sql);
        $count = $this->db->fetchValue($sql);

        if ($count == 0)
        {
            $sql = "insert into \"VideoTag\" (\"VideoUID\", \"TagText\") values ('?video_Id?', '?tag?')";
            $sql = str_replace("?video_Id?", $videoId, $sql);
            $sql = str_replace("?tag?", $tagText, $sql);
            $this->db->exesql($sql);
        }
    }

    //find all items tagged by the given tag, itemType = { Design, Mesh, Group, Texture, Video }
    private function GetItemIdsByTag($singleTag, $itemType)
    {
        $itemUID = $itemType."UID";
        $rs = $this->db->exesql('select "'.$itemUID.'" from "'.$itemType.'Tag" where "TagText"=\''.$singleTag.'\'');
        $resultArray = array();
        while($line = pg_fetch_array($rs))
        {
            $resultArray[] = "'".$line[$itemUID]."'";
        }

        return $resultArray;
    }

    //find all items tagged by the given tag array
    private function GetItemIdsByTags($tagsArray, $itemType)
    {
        $idArray = NULL;
        foreach ($tagsArray as $singleTag)
        {
            $newIdArray = $this->GetItemIdsByTag(strtolower($singleTag), $itemType);
            if ($idArray == NULL)
            {
                $idArray = $newIdArray;
            }
            else
            {
                $idArray = array_intersect($newIdArray, $idArray);
            }
        }
         
        return $idArray;
    }

    //find all users whose names match the pattern
    private function GetUserIdsByName($keywordArray)
    {
        $idArray = array();

        foreach ($keywordArray as $keyword)
        {
            $sql = "select \"UserUID\" from \"User\" where \"UserName\" ILIKE '%$keyword%' order by \"UserUID\" ";
            $userIds = $this->db->exesqlAndReturnArray($sql);

            if ($userIds)
            	$idArray = array_merge($idArray, $userIds);
        }

        return $idArray;
    }

    private function getUserViewingPolicy($isUserLoggedIn)
    {
        if (!$isUserLoggedIn)
            return $this->scopeWorldwide;
        else
        {
            $codes = $this->db->fetchArray("select \"UnlockCode\", \"CodeCategory\" from \"User\" where \"UserUID\"='$this->currentUserId'");
            if ($codes)
            {
                $codeID = (int)$codes["UnlockCode"];
                $categoryID = (int)$codes["CodeCategory"];

                // user isn't a student
                if ($codeID == 0)
                    return $this->scopeWorldwide;

                if ($categoryID == 0)
                {
                    $schoolViewingPolicy = $this->db->fetchValue("select \"ViewingPolicy\" from \"UnlockCodes\" where codeuid = '".$codeID."'");

                    if ($schoolViewingPolicy)
                    {
                        return $schoolViewingPolicy;
                    }
                }
                else
                {
                    $policyArray = $this->db->fetchArray("select a.\"ViewingPolicy\" as \"ClassViewingPolicy\", b.\"ViewingPolicy\" as \"SchoolViewingPolicy\" from \"CodeCategories\" a, \"UnlockCodes\" b where a.\"CategoryUID\" = '".$categoryID."' and b.codeuid = a.\"CodeUID\"");

                    if ($policyArray)
                    {
                        $schoolViewingPolicy = $policyArray["SchoolViewingPolicy"];
                        $classViewingPolicy = $policyArray["ClassViewingPolicy"];

                        if ($classViewingPolicy == $this->scopeDefault)
                            return $schoolViewingPolicy;
                        else
                            return $classViewingPolicy;
                    }
                }
            }
        }

        return $this->scopeClass;
    }

    private function getUserSharingPolicy($isUserLoggedIn)
    {
        if (!$isUserLoggedIn)
            return $this->scopeWorldwide;
        else
        {
            $codes = $this->db->fetchArray("select \"UnlockCode\", \"CodeCategory\" from \"User\" where \"UserUID\"='$this->currentUserId'");
            if ($codes)
            {
                $codeID = (int)$codes["UnlockCode"];
                $categoryID = (int)$codes["CodeCategory"];

                // user isn't a student
                if ($codeID == 0)
                    return $this->scopeWorldwide;

                if ($categoryID == 0)
                {
                    $schoolSharingPolicy = $this->db->fetchValue("select \"SharingPolicy\" from \"UnlockCodes\" where codeuid = " . $codeID . "");

                    if ($schoolSharingPolicy)
                    {
                        return $schoolSharingPolicy;
                    }
                }
                else
                {
                    $policyArray = $this->db->fetchArray("select a.\"SharingPolicy\" as \"ClassSharingPolicy\", b.\"SharingPolicy\" as \"SchoolSharingPolicy\" from \"CodeCategories\" a, \"UnlockCodes\" b where a.\"CategoryUID\" = " . $categoryID . " and b.codeuid = a.\"CodeUID\"");

                    if ($policyArray)
                    {
                        $schoolSharingPolicy = $policyArray["SchoolSharingPolicy"];
                        $classSharingPolicy = $policyArray["ClassSharingPolicy"];

                        if ($classSharingPolicy == $this->scopeDefault)
                            return $schoolSharingPolicy;
                        else
                            return $classSharingPolicy;
                    }
                }
            }
        }

        return $this->scopeClass;
    }

    private function InsertDesignIntoRenderQueue($designUID, $frame, $isCover, $createPurchaseItem, $exportSTL = 't')
    {
        if ($isCover == 't')
        {
            // if there is already a cover waiting to be rendered, remove it
            $sql = "delete from \"DesignsToRender\" where \"DesignUID\" = '?design_Id?' and \"IsCover\" = 't'";
            $sql = str_replace("?design_Id?", $designUID, $sql);
            $this->db->exesql($sql);
        }
        $requestUID = $this->GUID();
        $sql = "insert into \"DesignsToRender\" (\"RequestUID\", \"DesignUID\", \"Frame\", \"IsCover\", \"CreatePurchaseItem\") values ('?request_Id?', '?design_Id?', ?frame?, '?isCover?', '?createPurchaseItem?')";
        $sql = str_replace("?request_Id?", $requestUID, $sql);
        $sql = str_replace("?design_Id?", $designUID, $sql);
        $sql = str_replace("?frame?", $frame, $sql);
        $sql = str_replace("?isCover?", $isCover, $sql);
        $sql = str_replace("?createPurchaseItem?", $createPurchaseItem, $sql);
        $this->db->exesql($sql);

        if ($exportSTL)
        {
            // delete previous requests for this design if just requested by the system (ie not a user)
            $sql = "delete from \"DesignsToExport\" where \"DesignUID\" = '?design_Id?' and \"UserUID\" = -1";
            $sql = str_replace("?design_Id?", $designUID, $sql);
            $this->db->exesql($sql);

            // delete previous requests for this design if just requested by the system (ie not a user)
            $sql = "select count(\"DesignUID\") from \"Design\" where \"DesignUID\" = '?design_Id?' and \"Type\" = 1 and length(\"Data\") = 0 and length(\"OtherData\") = 0";
            $sql = str_replace("?design_Id?", $designUID, $sql);
            $count = $this->db->fetchValue($sql);

            if ($count == 0)
            {
                $this->InsertDesignIntoExportQueue($designUID, $requestUID);
            }
        }
    }

    function InsertDesignIntoExportQueue($designUID, $requestUID = null, $ReceiverEmail = '', $ReceiverAddress = '', $orderPrint = 'f')
    {
        if ($requestUID == null)
            $requestUID = $this->GUID();
  
        // delete previous requests for this design if not an email request
        $sql = "delete from \"DesignsToExport\" where \"DesignUID\" = '$designUID' and \"Email\" = ''";
        $this->db->exesql($sql);
 
        $sql = "insert into \"DesignsToExport\" (\"RequestUID\", \"DesignUID\", \"Email\", \"Address\", \"UserUID\", \"OrderPrint\") values ('?request_Id?', '?design_Id?', '?email?', '?address?', '?my_Id?', '?order_print?')";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?request_Id?", $requestUID, $sql);
        $sql = str_replace("?design_Id?", $designUID, $sql);
        $sql = str_replace("?email?", $ReceiverEmail, $sql);
        $sql = str_replace("?address?", $ReceiverAddress, $sql);
        $sql = str_replace("?order_print?", $orderPrint, $sql);
        $queryResult = $this->db->exesql($sql);
        $querySucceeded = pg_affected_rows($queryResult) > 0; 

        return $querySucceeded ? 1 : 0;
    }

    function GetDesignsToRender()
    {
        $limit = $this->getCleanValueFromArguments('Limit');

        // override limit
        $limit = 1;

        $sql = "select \"RequestUID\", \"DesignUID\", \"Frame\", \"IsCover\" from \"DesignsToRender\" where \"ProcessingTimeLimit\" < LOCALTIMESTAMP and attempts < 3 order by \"RequestNumber\" asc limit $limit offset 0";
        $designs = $this->db->sqlToArray($sql);

        if ($designs)
        {
            $idArray = array();
            for ($i=0; $i < count($designs); $i++)
            {
                $idArray[] = "'" . $designs[$i]['RequestUID'] . "'";
            }
            $idString = implode(',', $idArray);
            if ($idString != "")
            {
                $serverIP = $_SERVER['REMOTE_ADDR'];
                $serverName = $this->db->fetchValue("select name from generator_servers where ip = '$serverIP'");

                $sql = "update \"DesignsToRender\" set \"ProcessingTimeLimit\" = LOCALTIMESTAMP + interval '1 hour', attempts = attempts + 1, notes = 'Server = $serverName' where \"RequestUID\" in ($idString)";
                $this->db->exesql($sql);
            }

            $arr["designs"] = $designs;
        }
        else
        {
            $idString = "";
        }

        $this->UpdateGeneratorServerData($idString);

        $arr["result"] = $designs ? 1 : 0;

        return json_encode($arr);
    }


    function UpdateGeneratorServerData($idString)
    {
        date_default_timezone_set("UTC");
        $now = new DateTime;
        $nowStr = $now->format('Y-m-d H:i:s');

        // get last request time
        $serverIP = $_SERVER['REMOTE_ADDR'];
        $lastRequestTime = $this->db->fetchValue("select last_request from generator_servers where ip = '$serverIP'");

        // calculate interval
        $last = new DateTime($lastRequestTime);
        $interval = $last->diff($now)->i;

        // update max request interval since reboot
        $maxRequestInterval = $this->db->fetchValue("select max_request_interval from generator_servers where ip = '$serverIP'");
        $previousStatus = $this->db->fetchValue("select status from generator_servers where ip = '$serverIP'");
        if ($interval > $maxRequestInterval && ($previousStatus == 'waiting' || $previousStatus == 'processing'))
            $this->db->exesql("update generator_servers set max_request_interval=$interval where ip = '$serverIP'");

        $this->db->exesql("update generator_servers set last_request='$nowStr' where ip = '$serverIP'");

        if ($idString == "")
        {
            $this->db->exesql("update generator_servers set status='waiting' where ip = '$serverIP'");
        }
        else
        {
            $this->db->exesql("update generator_servers set status='processing' where ip = '$serverIP'");
            $this->db->exesql("update generator_servers set last_designs=$idString where ip = '$serverIP'");
        }
    }

    function AddDesignToRender()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $IsCover = $this->getCleanValueFromArguments('IsCover', true);
        $Frame = $this->getCleanValueFromArguments('Frame', true);
        $CreatePurchaseItem = $this->getCleanValueFromArguments('CreatePurchaseItem') == 'True' ? 't' : 'f';

        $this->InsertDesignIntoRenderQueue($DesignUID, $Frame, $IsCover, $CreatePurchaseItem);
    }

    function RefreshRenderRequest()
    {
        $RequestUID = $this->getCleanValueFromArguments('RequestUID', true);
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $sql = "delete from \"DesignsToRender\" where \"RequestUID\" = '?request_Id?'";
        }
        else
        {
            $sql = "update \"DesignsToRender\" set \"ProcessingTimeLimit\" = LOCALTIMESTAMP + interval '5 minutes' where \"RequestUID\" = '?request_Id?'";
        }
        $sql = str_replace("?request_Id?", $RequestUID, $sql);
        $this->db->exesql($sql);

        $arr["result"] = 1;
        return json_encode($arr);
    }

    function GetDesignsToExport()
    {
        $limit = $this->getCleanValueFromArguments('Limit');

        // override limit
        $limit = 1;

        $sql = "select \"RequestUID\", \"DesignUID\" from \"DesignsToExport\" where \"ProcessingTimeLimit\" < LOCALTIMESTAMP and \"IsProcessed\" = false and attempts < 3 order by \"Email\" desc, \"ProcessingTimeLimit\" asc, \"RequestNumber\" asc limit $limit offset 0";
        $designs = $this->db->sqlToArray($sql);

        if ($designs)
        {
            $idArray = array();
            $designUIDArray = array();
            for ($i=0; $i < count($designs); $i++)
            {
                $idArray[] = "'" . $designs[$i]['RequestUID'] . "'";
                $designUIDArray[] = "'" . $designs[$i]['DesignUID'] . "'";
            }
            $idString = implode(',', $idArray);
            $designUIDString = implode(',', $designUIDArray);
            if ($idString != "")
            {
                $serverIP = $_SERVER['REMOTE_ADDR'];
                $serverName = $this->db->fetchValue("select name from generator_servers where ip = '$serverIP'");

                $sql = "update \"DesignsToExport\" set \"ProcessingTimeLimit\" = LOCALTIMESTAMP + interval '1 hour', attempts = attempts + 1, notes = 'Server = $serverName' where \"RequestUID\" in ($idString)";
                $this->db->exesql($sql);
            }

            $arr["designs"] = $designs;
        }
        else
        {
            $idString = "";
            $designUIDString = "";
        }

        $this->UpdateGeneratorServerData($designUIDString);

        $arr["result"] = $designs ? 1 : 0;

        return json_encode($arr);
    }

    function OrderPrintOfDesign()
    {
        $this->arguments['orderPrint'] = 't';
        return $this->ExportDesignToSTL();
    }

    function ExportDesignToSTL()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["result"] = 0;
        }
        else
        {
            $ReceiverEmail = $this->getCleanValueFromArguments('ReceiverEmail', true);
            $ReceiverAddress = $this->getCleanValueFromArguments('ReceiverAddress');
            $orderPrint = isset($this->arguments["orderPrint"]) ? 't' : 'f';

            // add request if not pre-existing
            $sql = "select count(\"RequestUID\") as final_count from \"DesignsToExport\" where \"DesignUID\"='?design_Id?' and \"UserUID\"='?my_Id?' and \"Email\"='?email?' and \"Address\"='?address?' and \"OrderPrint\"='?order_print?' and \"IsProcessed\" = 'False'";
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $sql = str_replace("?email?", $ReceiverEmail, $sql);
            $sql = str_replace("?address?", $ReceiverAddress, $sql);
            $sql = str_replace("?order_print?", $orderPrint, $sql);
            $count = $this->db->fetchValue($sql);
            if($count > 0)
            {
                $arr["result"] = 0;
                if ($orderPrint == 't')
                {
                    $arr["msg"] = "You have already ordered a print of this design. Please contact our support team if the process takes too long.";
                    $arr["msgKey"] = 'ServerMessage70';
                }
                else
                {
                    $arr["msg"] = "You have already requested STL of this design. Please contact our support team if the process takes too long.";
                    $arr["msgKey"] = 'ServerMessage71';
                }
            }
            else
            {
                // check whether user is allowed to request exports (if no unlock code, assume 'can export' flags are correct)
                $unlockCode = $this->db->fetchValue("select \"UnlockCode\" from \"User\" where \"UserUID\"='$this->currentUserId'");
                if ($unlockCode != 0)
                {
                    $codeActivationDate = $this->db->fetchValue("select unlock_code_activation_date from \"User\" where \"UserUID\"='$this->currentUserId'");
                    $codeDurationDays = $this->db->fetchValue("select duration_days from \"UnlockCodes\" where codeuid = $unlockCode");

                    if ($codeActivationDate != null && $codeDurationDays > 0)
                    {
                        date_default_timezone_set("UTC");
                        $codeDurationInterval = new DateInterval('P'.$codeDurationDays.'D');
                        $codeActivationTime = new DateTime($codeActivationDate);
                        $codeActivationExpiry = $codeActivationTime->add($codeDurationInterval);

                        $now = new DateTime;
                        if ($now > $codeActivationExpiry)
                        {
                            $arr["result"] = 0;
                            $arr["msg"] = "Your licence key has expired. Please contact our support team at ".$this->support_email_address;
                            $arr["msgKey"] = 'ServerMessageCodeExpired';
                            return json_encode($arr);
                        }
                    }
                }


                $requestUID = $this->GUID();
                $arr["result"] = $this->InsertDesignIntoExportQueue($DesignUID, $requestUID, $ReceiverEmail, $ReceiverAddress, $orderPrint);

                // send notification
                $userName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\"='$this->currentUserId'");
                $subject = $arr["result"] == 1 ? "Added design to STL export queue" : "Failed to add design to STL export queue";
                if ($orderPrint == 't')
                {
                    $subject = $subject . " (print order)";
                    $message = "Design print order<br/><br/>";
                }
                else
                    $message = "";

                $message = $message . "Application: " . $this->application_name . "<br/>User name: " . $userName . "<br/>User ID: " . $this->currentUserId . "<br/>Receiver's email: " . $ReceiverEmail;
                if ($orderPrint == 't')
                    $message = $message . "<br/>Receiver's postal address: " . $ReceiverAddress;

                $message = $message . "<br/>Design ID: " . $DesignUID;
                $designInfo = $this->db->fetchArray("select \"DisplayName\", \"Type\", \"PictureUrl\" from \"Design\" where \"DesignUID\"='$DesignUID'");
                if ($designInfo)
                {
                    $message = $message . "<br/>Design name: " . $designInfo['DisplayName'] . "<br/>Design picture: " . WEBROOT . $designInfo['PictureUrl'] . "<br/>Design type: " . $designInfo['Type'];
                }
                $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');


                if ($ReceiverEmail)
                {
                    // send immediately if STL file exists
                    $fileName = 'stl/' . substr($DesignUID, 0, 2) . '/' . $DesignUID . '.stl';
                    if (file_exists($fileName))
                    {
                        $this->arguments['RequestUID'] = $requestUID;
                        $this->SendExportedDesign(True);
                    }
                }
                else
                {
                    // delay processing for a short time in case user is still editing this design
                    date_default_timezone_set("UTC");
                    $delayDuration = new DateInterval('PT2M');
                    $processingTime = new DateTime;
                    $processingTime = $processingTime->add($delayDuration);
                    $processingTimeStr = $processingTime->format('Y-m-d H:i:s');
                    $this->db->exesql("update \"DesignsToExport\" set \"ProcessingTimeLimit\" = '$processingTimeStr' where \"RequestUID\" = '$requestUID'");
                }
            }
        }

        return json_encode($arr);
    }

    function PrioritiseDesignExport()
    {
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $this->db->exesql("update \"DesignsToExport\" set \"ProcessingTimeLimit\" = '2000-01-01' where \"DesignUID\" = '$DesignUID' and \"IsProcessed\" = 'f'");
    }

    function RefreshExportRequest()
    {
        $RequestUID = $this->getCleanValueFromArguments('RequestUID', true);
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $sql = "delete from \"DesignsToExport\" where \"RequestUID\" = '?request_Id?'";
        }
        else
        {
            $sql = "update \"DesignsToExport\" set \"ProcessingTimeLimit\" = LOCALTIMESTAMP + interval '4 hours' where \"RequestUID\" = '?request_Id?'";
        }
        $sql = str_replace("?request_Id?", $RequestUID, $sql);
        $this->db->exesql($sql);

        $arr["result"] = 1;
        return json_encode($arr);
    }
    
    function SendExportedDesign($useSavedStl = False)
    {
        $RequestUID = $this->getCleanValueFromArguments('RequestUID', true);
        if ($useSavedStl || is_uploaded_file($_FILES['STLData']['tmp_name']) && $_FILES['STLData']['error'] == 0)
        {
            $requestInfo = $this->db->fetchArray("select \"RequestNumber\", \"Email\", \"UserUID\", \"DesignUID\", \"OrderPrint\" from \"DesignsToExport\" where \"RequestUID\"='$RequestUID'");
            if ($requestInfo)
            {
                date_default_timezone_set("UTC");

                $userUID = $requestInfo['UserUID'];
                $userName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\" = '$userUID'");
                $userDisplayName = $this->db->fetchValue("select \"DisplayName\" from \"User\" where \"UserUID\" = '$userUID'");

                // make sure folder exists for stl file(s)
                $pathName = 'stl/' . substr($requestInfo['DesignUID'], 0, 2);
                if (!file_exists($pathName))
                    mkdir($pathName, 0775, true);

                // get description of part
                $partName = $this->getCleanValueFromArguments('PartName', false);

                if ($partName && $partName != '')
                {
                    // there are multiple parts for this design
                    $fileName = $partName . '.stl';

                    // ensure folder exists for stl files
                    $pathName = $pathName . '/' . $requestInfo['DesignUID'];
                    if (!file_exists($pathName))
                    {
                        if (!mkdir($pathName, 0775, true))
                           error_log("mkdir failed for path " . $pathName);
                    }
                }
                else
                {
                    $fileName = $requestInfo['DesignUID'] . '.stl';
                }

                //$fileName = date("Y_m_d_H_i_s", time()) . '-' . $requestInfo["RequestNumber"];
                $fileRelativePath = $pathName . '/' . $fileName;
                if ($useSavedStl)
                    $stlPath = $fileRelativePath;
                else
                {
                    $fileHandler = new FileHandler();
                    $stlPath = $fileHandler->moveFile($_FILES['STLData']['tmp_name'], $fileRelativePath);
                }

                if ($stlPath == '')
                {
                    $arr["result"] = 0;
                    $arr["msg"] = 'stl path empty';
                }
                else
                {
                    //$log = new Logger('api');
                    //$log->pushHandler(new StreamHandler('/var/log/picto/api.log', Logger::INFO));
                    //$log->addInfo('stl saved to ' . $stlPath);

                    $designUID = $requestInfo['DesignUID'];

                    //error_log("Order print " . $requestInfo["OrderPrint"]);

                    if ($requestInfo["Email"] != "" && strtolower($requestInfo["OrderPrint"]) == 'f')
                    {
                        $designName = $this->db->fetchValue("select \"DisplayName\" from \"Design\" where \"DesignUID\"='$designUID'");
                        $authorName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\" in (select \"OwnerUID\" from \"Design\" where \"DesignUID\"='$designUID')");


                        // copy file to a friendlier name, keeping any part of the filename after an underscore (if exists)
                        if ($partName && $partName != '')
                            $friendlyFileName = $authorName . '_' . $designName . '_' . $fileName;
                        else
                            $friendlyFileName = $authorName . '_' . $designName . '.stl';

                        // Remove anything which isn't a word, whitespace, number
                        // or any of the following caracters -_~,;:[]().
                        $friendlyFileName = preg_replace("([^\w\s\d\-_~,;:\[\]\(\).])", '', $friendlyFileName);
                        // Remove any runs of periods
                        $friendlyFileName = preg_replace("([\.]{2,})", '', $friendlyFileName);

                        // copy file
                        $stlPath = FileHandler::path . $stlPath;
                        $friendlyPath = str_replace($fileName, $friendlyFileName, $stlPath);
                        copy($stlPath, $friendlyPath);

                        $subject = "Your exported STL File for " . $designName;
                        //$message = "Hello " . $userName . ",";
                        //$message = $message . "<br/><br/>Your STL download from Makers Empire for " . $designName . " is attached.";
                        //$message = $message . "<br/><br/>If you experience any issues at all, please contact us by replying to this email.";
                        //$message = $message . "<br/><br/>Thanks,<br/>Makers Empire team";
                        //$this->SendEmailSendGrid($requestInfo["Email"], $subject, $message, $this->info_email_address, 'Makers Empire Support', $friendlyPath);
                        $globalMergeVars = array(
                            array('name' => 'USERNAME', 'content' => $userName),
                            array('name' => 'DESIGNNAME', 'content' => $designName),
                            array('name' => 'DESIGNID', 'content' => $requestInfo["DesignUID"])
                        );
                        $b64_stl = base64_encode(file_get_contents($friendlyPath));
                        $attachmentArray = array(
                            array('type' => 'application/sla', 'name' => $friendlyFileName, 'content' => $b64_stl)
                        );
                        $this->SendEmailMandrill("stl-email", $globalMergeVars, $requestInfo["Email"], $subject, $this->info_email_address, $this->application_name, "false", $attachmentArray);

                        // log in web_logs table
                        $toEmail = $requestInfo["Email"];
                        $sql = "insert into web_logs (log_type, log_level, message, created_at) values (1, 3, 'trying to email : $toEmail', localtimestamp)";
                        $this->db->exesql($sql);

                        $message = "Application: " . $this->application_name . "<br/>Request ID: " . $RequestUID . "<br/>Design ID: " . $requestInfo["DesignUID"] . "<br/>Design title: " . $designName;
                        $message = $message . "<br/>User name: " . $userName . "<br/>User ID: " . $requestInfo['UserUID'];
                        $message = $message . "<br/>Receiver's email: " . $requestInfo["Email"] . "<br/>File path: " . $fileRelativePath;
                        $this->SendEmailSendGrid($this->info_email_address, "STL file was exported and sent to the user", $message, $this->info_email_address, $this->application_name . ' Support', $friendlyPath);

                        // changed to keep entries that have been requested by users
                        //$this->db->exesql("delete from \"DesignsToExport\" where \"RequestUID\" = '$RequestUID'");
                        $this->db->exesql("update \"DesignsToExport\" set \"IsProcessed\" = true where \"RequestUID\" = '$RequestUID'");

                        //$log->addInfo('stl emailed to ' . $requestInfo["Email"] . ' from ' . $friendlyPath);
                    }
                    else if (strtolower($requestInfo["OrderPrint"]) == 't')
                    {
                        $newPathName = 'stl/order';
                        if (!file_exists($newPathName))
                            mkdir($newPathName, 0775, true);

                        copy($fileRelativePath, $newPathName . '/' . $requestInfo["Email"] . '_' . $requestInfo["UserUID"] . '_' . $userName . '_' . $fileName);

                        $this->db->exesql("update \"DesignsToExport\" set \"IsProcessed\" = true where \"RequestUID\" = '$RequestUID'");
                    }
                    else
                    {
                        $this->db->exesql("delete from \"DesignsToExport\" where \"RequestUID\" = '$RequestUID'");
                    }


                    $arr["result"] = 1;

                    // set date of STL file
                    $now = new DateTime;
                    $nowStr = $now->format('Y-m-d H:i:s');
                    $this->db->exesql("update \"Design\" set stl_date='$nowStr' where \"DesignUID\" = '$designUID'");

                    // send latest STL to makerbot if syncing - needs to do this for design owner and anyone who likes the design
                    $ownerUID = $this->db->fetchValue("select \"OwnerUID\" from \"Design\" where \"DesignUID\"='$designUID'");
                    $this->SyncToMakerBot($ownerUID);

                    $sql = "select \"UserUID\" from \"Like\" where \"DesignUID\"='$designUID'";
                    $likers = $this->db->sqlToArray($sql);
                    if ($likers)
                    {
                        for ($i=0; $i < count($likers); $i++)
                            $this->SyncToMakerBot($likers[$i]["UserUID"]);
                    }
                }
            }
            else
            {
                $arr["result"] = 1;
                $arr["msg"] = 'request response empty (probably deleted due to newer request for same design being added)';
             }
        }
        else
        {
            $arr["result"] = 0;
            $arr["msg"] = 'uploaded file error ' .  $_FILES['STLData']['error'] . ' name ' . $_FILES['STLData']['tmp_name'];
        }

        if ($arr["result"] == 0)
        {
            $this->SendEmailSendGrid($this->info_email_address, "Error in SendExportedDesign", "Request UID: " . $RequestUID . "\n" . $arr["msg"], $this->info_email_address, $this->application_name . ' Support');
        }

        return json_encode($arr);
    }

    function PreviewDesign()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }
        $getDoodlerData = $this->getCleanValueFromArguments('GetDoodlerData') == 1;

        $userViewingPolicy = $this->getCleanValueFromArguments('ViewingPolicy');
        if ($userViewingPolicy == '')
        {
            $userViewingPolicy = $this->getUserViewingPolicy($isUserLoggedIn);
        }

        // getting design data, requested as a guest
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        $sql = "select d.\"PictureUrl\", d.\"ThumbnailUrl\", d.\"DisplayName\", d.\"Description\", d.\"Type\", d.\"Likes\", d.\"Comments\", d.\"IsShared\", d.\"ViewCount\", d.\"IsCustomisable\", d.\"CreationDate\", d.\"ParentUID\", d.\"OwnerUID\", d.\"OtherData\", u.\"UserName\" as \"OwnerName\", u.\"UnlockCode\" as \"OwnerSchoolID\", u.\"CodeCategory\" as \"OwnerClassID\", encode(d.\"Data\", 'base64'), encode (d.\"CameraData\", 'base64') as cameradata, d.app_version_string from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where d.\"DesignUID\" = '?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);

        $ret = $this->db->fetchArray($sql);
        if (!$ret)
        {
            $arr["result"] = 0;
            $arr["msg"] = "Design was not found.";
            $arr["msgKey"] = 'ServerMessage72';
        }
        else
        {
            $canProceed = true;
            if ($userViewingPolicy != $this->scopeWorldwide)
            {
                // the author is not a student
                if ($ret["OwnerSchoolID"] == "0")
                {
                    $canProceed = false;

                    $arr["result"] = 0;
                    $arr["msg"] = "Your class policy does not allow to view that design.";
                    $arr["msgKey"] = 'ServerMessage73';
                }
                else
                {
                    if ($userViewingPolicy == $this->scopeAllSchools)
                    {
                        // no need to do anything else here - the author is not a student
                    }
                    else
                    {
                        $codes = $this->db->fetchArray("select \"UnlockCode\", \"CodeCategory\" from \"User\" where \"UserUID\"='$this->currentUserId'");
                        if ($codes)
                        {
                            $userSchoolID = $codes["UnlockCode"];
                            $userClassID = $codes["CodeCategory"];

                            if (($userViewingPolicy == $this->scopeClass && $ret["OwnerClassID"] != $userClassID) || ($userViewingPolicy == $this->scopeSchool && $ret["OwnerSchoolID"] != $userSchoolID))
                            {
                                $canProceed = false;

                                $arr["result"] = 0;
                                $arr["msg"] = "Your class policy does not allow to view that design.";
                                $arr["msgKey"] = 'ServerMessage73';
                            }
                        }
                        else
                        {
                            $canProceed = false;

                            $arr["result"] = 0;
                            $arr["msg"] = "Unexpected error has occurred while getting class info.";
                            $arr["msgKey"] = 'ServerMessage74';
                        }
                    }
                }
            }

            if ($canProceed)
            {
                $bForce = $this->getCleanValueFromArguments('Force');
                if ($ret["IsShared"] == 't' || $bForce == 1)
                {
                    $arr["result"] = 1;
                    $arr["DesignUID"] = $DesignUID;
                    if ($ret["ParentUID"] == null || $ret["ParentUID"] == "")
                        $arr["ParentUID"] = "";
                    else if ($ret["ParentUID"] == "00000000-0000-0000-0000-000000000000")
                        $arr["ParentUID"] = "00000000-0000-0000-0000-000000000000";
                    else
                    {
                        $parentData = $this->db->fetchArray("select d.\"DisplayName\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\" from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where d.\"DesignUID\" = '" . $ret["ParentUID"] . "'");
                        if ($parentData)
                        {
                            $arr["ParentUID"] = $ret["ParentUID"];
                            $arr["ParentDisplayName"] = $parentData["DisplayName"];
                            $arr["ParentOwnerUID"] = $parentData["OwnerUID"];
                            $arr["ParentOwnerName"] = $parentData["OwnerName"];
                        }
                        else
                        {
                            # we didn't find the parent or failed to get the info
                            $arr["ParentUID"] = "";
                        }
                    }
                    $arr["Type"] = $ret["Type"];
                    $arr["PictureUrl"] = $ret["PictureUrl"];
                    $arr["ThumbnailUrl"] = $ret["ThumbnailUrl"];
                    $arr["OtherData"] = $ret["OtherData"];
                    $arr["DisplayName"] = $ret["DisplayName"];
                    $arr["Description"] = $ret["Description"];
                    $arr["Likes"] = $ret["Likes"];
                    $arr["Comments"] = $ret["Comments"];
                    $arr["IsShared"] = $ret["IsShared"];
                    $arr["ViewCount"] = $ret["ViewCount"];
                    $arr["IsCustomisable"] = $ret["IsCustomisable"];
                    $arr["CreationDate"] = $ret["CreationDate"];
                    $arr["OwnerUID"] = $ret["OwnerUID"];
                    $arr["OwnerName"] = $ret["OwnerName"];
                    $arr["Data"] = ($arr["Type"] == '2' && !$getDoodlerData) ? '' : $ret["encode"];
                    if ($ret["cameradata"] != null)
                        $arr["CameraData"] = $ret["cameradata"];
                    if ($ret["app_version_string"] != null)
                        $arr["AppVersion"] = $ret["app_version_string"];

                    if ($this->getCleanValueFromArguments("tData"))
                        $arr['DesignTags'] = $this->GetDesignTags($DesignUID, "true");
                    else
                        $arr['DesignTags'] = $this->GetDesignTags($DesignUID, "false");


                    $photos = $this->GetDesignPhotos($DesignUID);
                    if ($photos && $photos != '')
                        $arr['DesignPhotos'] = $photos;
                    if ($isUserLoggedIn)
                    {
                        $arr['IsLikedByMe'] = $this->IsDesignLikedByMe($DesignUID);
                        $arr['IsFavorited'] = $this->IsDesignFavoritedByMe($DesignUID);
                    }
                    else
                    {
                        $arr['IsLikedByMe'] = "0";
                        $arr['IsFavorited'] = "0";
                    }
                }
                else
                {
                    $arr["result"] = 0;
                    $arr["msg"] = "Design is no longer shared.";
                    $arr["msgKey"] = 'ServerMessage75';
                }
            }
        }

        return json_encode($arr);
    }

    function GetDesignData()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }
        $getDoodlerData = $this->getCleanValueFromArguments('GetDoodlerData') == 1;

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $arr["DesignUID"] = $DesignUID;

        $sql = "select count(*) as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["result"] = 0;
            $arr["msg"] = "Design was not found.";
            $arr["msgKey"] = 'ServerMessage72';
        }
        else
        {
            $sql = "select encode(\"Data\", 'base64'), encode(\"CameraData\", 'base64') as cameradata, app_version_string, \"OtherData\", \"Type\" from \"Design\" where \"DesignUID\" = '$DesignUID'";
            $result = $this->db->fetchArray($sql);

            if (!$result)
            {
                $arr["result"] = 0;
                $arr["msg"] = "A problem occurred while getting design data.";
                $arr["msgKey"] = 'ServerMessage77';
            }
            else
            {
                $arr["result"] = 1;
                $arr["encode"] = ($result['Type'] == '2' && !$getDoodlerData) ? '' : $result['encode'];
                $arr["OtherData"] = $result['OtherData'];
                $arr["CameraData"] = $result['cameradata'];
                if ($result["app_version_string"] != null)
                    $arr["AppVersion"] = $result["app_version_string"];
            }
        }

        return json_encode($arr);
    }

    function GetMatchingLevels()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $userSchoolID = 0;
        $userClassID = 0;
        $codes = $this->db->fetchArray("select \"UnlockCode\", \"CodeCategory\" from \"User\" where \"UserUID\"='$this->currentUserId'");
        if ($codes)
        {
            if ($codes["UnlockCode"] != null)
                $userSchoolID = $codes["UnlockCode"];
            if ($codes["CodeCategory"] != null)
                $userClassID = $codes["CodeCategory"];
        }
        else if ($isUserLoggedIn)
        {
            $resultArray["result"] = 0;
            $resultArray["msg"] = "Unexpected error has occurred while getting class info.";
            $resultArray["msgKey"] = 'ServerMessage74';
            return json_encode($resultArray);
        }

        $limit = $this->getCleanValueFromArguments('Limit');
        $offset = $this->getCleanValueFromArguments('Offset');
        if (!$offset)
        	$offset = 0;
        
        $keywords = $this->getCleanValueFromArguments('Keywords');

        $fromMyDesigns = false;
        if (isset($this->arguments["MyDesigns"]))
        {
            $fromMyDesigns = $this->getCleanValueFromArguments('MyDesigns') == 'True';
        }

        $showBy = $this->getCleanValueFromArguments('ShowBy');
        $orderBy = $this->getCleanValueFromArguments('OrderBy');

        if (isset($this->arguments["GetData"]))
        {
            $getData = $this->getCleanValueFromArguments('GetData') == 'True';
        }
        else
        {
            $getData = true;
        }
        $getDoodlerData = $this->getCleanValueFromArguments('GetDoodlerData') == 1;

        // for backward compatibility
        if (isset($this->arguments["IsFavorited"]))
        {
            $getLiked = $this->getCleanValueFromArguments('IsFavorited') == 'True'; // it returns liked designs after recent changes
        }
        else
        {
            $getLiked = $orderBy == "favorited"; // it returns liked designs after recent changes
            if ($getLiked)
            {
                $orderBy = "views";
            }
        }

        $userViewingPolicy = $this->getCleanValueFromArguments('ViewingPolicy');
        $viewingPolicyCondition = "";
        if ($userViewingPolicy == '')
        {
            $userViewingPolicy = $this->getUserViewingPolicy($isUserLoggedIn);
        }
        if ($userViewingPolicy != $this->scopeWorldwide)
        {
            if ($userViewingPolicy == $this->scopeAllSchools)
            {
                $viewingPolicyCondition = " and u.\"UnlockCode\" <> 0";
            }
            else if ($userViewingPolicy == $this->scopeClass)
            {
                $viewingPolicyCondition = " and u.\"CodeCategory\" = $userClassID";
            }
            else if ($userViewingPolicy == $this->scopeSchool)
            {
                $viewingPolicyCondition = " and u.\"UnlockCode\" = $userSchoolID";
            }
        }

        $likedCondition = "";
        if ($getLiked)
            $likedCondition = "and d.\"DesignUID\" in (select \"DesignUID\" from \"Like\" where \"UserUID\"=$this->currentUserId)";

        $winnerCondition = "";
        if (isset($this->arguments["HallOfFame"]))
            $winnerCondition = "and d.\"DesignUID\" in (select design_id from competition_submissions where status is not null)";

        $ownerUID = $this->getCleanValueFromArguments('OwnerUID');
        if ($ownerUID != '')
        {
            $ownerUID = " and d.\"OwnerUID\" = " . $ownerUID;
            $fromMyDesigns = false; // this shouldn't be set to true when we're searching by author, so we clear the flag just to be sure
        }

		// split keywords into array, avoiding empty keywords in array, then find designs that match due to tags or usernames
		$keywordArray = preg_split('/ /', $keywords, -1, PREG_SPLIT_NO_EMPTY);
        $designsIdString = "";
        $usersIdString = "";
        if(count($keywordArray) > 0)
        {
            $idArray = $orderBy == "favorited" ? array_intersect($this->GetItemIdsByTags($keywordArray, "Design"), $likedIdArray) : $this->GetItemIdsByTags($keywordArray, "Design");
            $designsIdString = implode(',', $idArray);

            if ($ownerUID == '')
            {
                $idArray = $this->GetUserIdsByName($keywordArray);
                $usersIdString = implode(',', $idArray);
            }
        }

		// create query text for excluding specific designs from results (was previously used as a laborious way of doing offsets)
        $designsToSkip = $this->getCleanValueFromArguments('DesignsToSkip');
        if ($designsToSkip != '')
        {
            $designsToSkipArray = explode(',', $designsToSkip);
            foreach ($designsToSkipArray as &$singleID)
            {
                $singleID = "'".$singleID."'";
            }
            unset($singleID);
            $designsToSkip = implode(',', $designsToSkipArray);
            $designsToSkip = " and d.\"DesignUID\" not in (" . $designsToSkip . ")";
        }

		// create query text for filtering by design type
        $designsType = $this->getCleanValueFromArguments('Type');
        if ($designsType != '')
        {
            if ($designsType == '0' || $designsType == '1')
            {
                $designsType = " and d.\"Type\" < 2";
            }
            else
            {
                $designsType = " and d.\"Type\" = " . $designsType;
            }
        }
        else
        {
            $designsType = " and d.\"Type\" != 7";
        }

		// create query text for ordering results
        $sqlOrderBy = "";
        if ($orderBy == "likes")
        {
            $sqlOrderBy = "\"Likes\"";
        }
        else if ($orderBy == "dates")
        {
            $sqlOrderBy = "\"CreationDate\"";
        }
        else
        {
            $sqlOrderBy = "\"ViewCount\"";
        }

		// create query text for limiting according to sharing/privacy policy
        $designSharingPolicy = " and (d.\"SharingPolicy\" = $this->scopeWorldwide or (d.\"SharingPolicy\" = $this->scopeAllSchools and $userSchoolID <> 0) or (d.\"SharingPolicy\" = $this->scopeSchool and $userSchoolID = u.\"UnlockCode\") or (d.\"SharingPolicy\" = $this->scopeClass and $userClassID = u.\"CodeCategory\"))";

        $sql = "";
        if ($designsIdString != "")
        {
        	// get designs that were found in tag search
            if ($getData)
            {
                $sql = "select d.\"DesignUID\", d.\"DisplayName\", d.\"Description\", d.\"Type\", d.\"Likes\", d.\"Comments\", d.\"PictureUrl\", d.\"ThumbnailUrl\", d.\"ViewCount\", d.\"IsCustomisable\", d.\"CreationDate\", d.\"ModificationDate\", d.\"ParentUID\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\", u.username_approved, d.\"OtherData\", encode(d.\"Data\", 'base64')
                    from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where (d.\"OwnerUID\" = $this->currentUserId or (d.\"IsShared\" = 't'" . $designSharingPolicy . $viewingPolicyCondition . ")) and d.\"DesignUID\" in ($designsIdString)" . $designsToSkip . $designsType . $ownerUID . " union ";
            }
            else
            {
                $sql = "select d.\"DesignUID\", d.\"DisplayName\", d.\"Description\", d.\"Type\", d.\"Likes\", d.\"Comments\", d.\"PictureUrl\", d.\"ThumbnailUrl\", d.\"ViewCount\", d.\"IsCustomisable\", d.\"CreationDate\", d.\"ModificationDate\", d.\"ParentUID\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\", u.username_approved
                    from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where (d.\"OwnerUID\" = $this->currentUserId or (d.\"IsShared\" = 't'" . $designSharingPolicy . $viewingPolicyCondition . ")) and d.\"DesignUID\" in ($designsIdString)" . $designsToSkip . $designsType . $ownerUID . " union ";
            }
        }
        
        // add desgins that are from current user or match keyword in title
        if ($getData)
        {
            $sql = $sql . "select d.\"DesignUID\", d.\"DisplayName\", d.\"Description\", d.\"Type\", d.\"Likes\", d.\"Comments\", d.\"PictureUrl\", d.\"ThumbnailUrl\", d.\"ViewCount\", d.\"IsCustomisable\", d.\"CreationDate\", d.\"ModificationDate\", d.\"ParentUID\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\", u.username_approved, d.\"OtherData\", encode(d.\"Data\", 'base64')
                from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where (d.\"OwnerUID\" = $this->currentUserId or (d.\"IsShared\" = 't'" . $designSharingPolicy . $viewingPolicyCondition . "))" . $designsToSkip . $designsType . $ownerUID;
        }
        else
        {
            $sql = $sql . "select d.\"DesignUID\", d.\"DisplayName\", d.\"Description\", d.\"Type\", d.\"Likes\", d.\"Comments\", d.\"PictureUrl\", d.\"ThumbnailUrl\", d.\"ViewCount\", d.\"IsCustomisable\", d.\"CreationDate\", d.\"ModificationDate\", d.\"ParentUID\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\", u.username_approved
                from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where (d.\"OwnerUID\" = $this->currentUserId or (d.\"IsShared\" = 't'" . $designSharingPolicy . $viewingPolicyCondition . "))" . $designsToSkip . $designsType . $ownerUID;
        }
        if ($fromMyDesigns)
        {
            $sql = $sql . " and (d.\"OwnerUID\" = $this->currentUserId)";
        }
        else
        {
            $doneFirst = FALSE;
            foreach ($keywordArray as $keyword)
            {
                if ($doneFirst == FALSE)
                {
                    $sql = $sql . " and (d.\"DisplayName\" ILIKE '%$keyword%'";
                    $doneFirst = true;
                }
                else
                {
                    $sql = $sql . "or d.\"DisplayName\" ILIKE '%$keyword%'";
                }
            }

            if ($usersIdString != "")
                $sql = $sql . " or d.\"OwnerUID\" in ($usersIdString))";
            else if ($doneFirst)
                $sql = $sql . ")";
        }

        // limit results to just featured designs if required
        if (isset($this->arguments["IsFeatured"]))
            $sql = $sql . " and d.\"DesignUID\" in (select \"DesignUID\" from \"DesignTag\" where \"TagText\"='_upvoted')";

        // limit to just liked designs if required, and get desired number of results from offset
        $sql = $sql . " $likedCondition $winnerCondition order by $sqlOrderBy $showBy, \"ModificationDate\" desc limit $limit offset $offset";
        $designs = $this->db->sqlToArray($sql);

        if ($designs)
        {
            for ($i=0; $i < count($designs); $i++)
            {
                if ($getData && !$getDoodlerData && $designs[$i]['Type'] == '2')
                {
                    $designs[$i]['encode'] = '';
                }

                // if this username has not been approved, let's replace with ***
                if ($designs[$i]["username_approved"] == 'f')
                    $designs[$i]["OwnerName"] = "*******";

                if ($this->getCleanValueFromArguments("tData"))
                        $designs[$i]['DesignTags'] = $this->GetDesignTags($designs[$i]['DesignUID'], "true");
                    else
                        $designs[$i]['DesignTags'] = $this->GetDesignTags($designs[$i]['DesignUID'], "false");

                $photos = $this->GetDesignPhotos($designs[$i]['DesignUID']);
                if ($photos && $photos != '')
                    $designs[$i]['DesignPhotos'] = $photos;
                if ($isUserLoggedIn)
                {
                    $designs[$i]['IsLikedByMe'] = $this->IsDesignLikedByMe($designs[$i]['DesignUID']);
                    if ($orderBy == "favorited")
                        $designs[$i]['IsFavorited'] = '1';
                    else
                        $designs[$i]['IsFavorited'] = $this->IsDesignFavoritedByMe($designs[$i]['DesignUID']);
                }
                else
                {
                    $designs[$i]['IsLikedByMe'] = "0";
                    $designs[$i]['IsFavorited'] = "0";
                }

                if ($designs[$i]["ParentUID"] == null)
                    $designs[$i]["ParentUID"] = "";
                else if ($designs[$i]["ParentUID"] != "" && $designs[$i]["ParentUID"] != "00000000-0000-0000-0000-000000000000")
                {
                    $parentData = $this->db->fetchArray("select d.\"DisplayName\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\", u.username_approved from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where d.\"DesignUID\" = '" . $designs[$i]["ParentUID"] . "'");
                    if ($parentData)
                    {
                        $designs[$i]["ParentDisplayName"] = $parentData["DisplayName"];
                        $designs[$i]["ParentOwnerUID"] = $parentData["OwnerUID"];
                        if ($parentData["username_approved"] == 'f')
                            $designs[$i]["ParentOwnerName"] = "*****";
                        else
                        $designs[$i]["ParentOwnerName"] = $parentData["OwnerName"];
                    }
                    else
                    {
                        # we didn't find the parent or failed to get the info
                        $designs[$i]["ParentUID"] = "";
                    }
                }

                // check if the design is a winner
                $designUID = $designs[$i]["DesignUID"];
                $sql = "select status from competition_submissions where design_id = '$designUID' and status is not null";
                $exists = $this->db->fetchValue($sql);
                if ($exists)
                {
                    $designs[$i]["winner_status"] = $exists;
                }
            }

            $resultArray["designs"] = $designs;
        }

        $resultArray["result"] = $designs ? 1 : 0;

        return json_encode($resultArray);
    }

    function GetOwnedLevels()
    {
        $this->checkUser(true);

        $designsType = $this->getCleanValueFromArguments('Type');
        if ($designsType != '')
        {
            if ($designsType == '0' || $designsType == '1')
            {
                $designsType = " and d.\"Type\" < 2";
            }
            else
            {
                $designsType = " and \"Type\" = " . $designsType;
            }
        }

        $sql = "select \"DesignUID\", \"ModificationDate\", \"Likes\", \"Comments\", \"ViewCount\", \"IsShared\", \"IsCustomisable\", \"ParentUID\" from \"Design\" where \"OwnerUID\"='?my_Id?'" . $designsType;
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $designs = $this->db->sqlToArray($sql);

        if ($designs)
        {
            for ($i=0; $i < count($designs); $i++)
            {
                if ($this->getCleanValueFromArguments("tData"))
                    $designs[$i]['DesignTags'] = $this->GetDesignTags($designs[$i]['DesignUID'], "true");
                else
                    $designs[$i]['DesignTags'] = $this->GetDesignTags($designs[$i]['DesignUID'], "false");
                $photos = $this->GetDesignPhotos($designs[$i]['DesignUID']);
                if ($photos && $photos != '')
                    $designs[$i]['DesignPhotos'] = $photos;
                $designs[$i]['IsLikedByMe'] = $this->IsDesignLikedByMe($designs[$i]['DesignUID']);
                $designs[$i]['IsFavorited'] = $this->IsDesignFavoritedByMe($designs[$i]['DesignUID']);

                // check if the design is a winner
                $designUID = $designs[$i]["DesignUID"];
                $sql = "select status from competition_submissions where design_id = '$designUID' and status is not null";
                $exists = $this->db->fetchValue($sql);
                if ($exists)
                {
                    $designs[$i]["winner_status"] = $exists;
                }

                if ($designs[$i]["ParentUID"] == null)
                    $designs[$i]["ParentUID"] = "";
                else if ($designs[$i]["ParentUID"] != "" && $designs[$i]["ParentUID"] != "00000000-0000-0000-0000-000000000000")
                {
                    $parentData = $this->db->fetchArray("select d.\"DisplayName\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\", u.username_approved from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where d.\"DesignUID\" = '" . $designs[$i]["ParentUID"] . "'");
                    if ($parentData)
                    {
                        $designs[$i]["ParentDisplayName"] = $parentData["DisplayName"];
                        $designs[$i]["ParentOwnerUID"] = $parentData["OwnerUID"];
                        if ($parentData["username_approved"] == 'f')
                            $designs[$i]["ParentOwnerName"] = "*****";
                        else
                        $designs[$i]["ParentOwnerName"] = $parentData["OwnerName"];
                    }
                    else
                    {
                        # we didn't find the parent or failed to get the info
                        $designs[$i]["ParentUID"] = "";
                    }
                }
            }

            $resultArray["designs"] = $designs;
            $resultArray["result"] = 1;
        }
        else
        {
            $resultArray["result"] = 0;
        }

        return json_encode($resultArray);
    }

    function GetMissingOrOutdatedLevels()
    {
        $this->checkUser(true);

        $getDoodlerData = $this->getCleanValueFromArguments('GetDoodlerData') == 1;
        $designIDs = $this->getCleanValueFromArguments('DesignIDs', true);
        $designArray = explode(',', $designIDs);
        foreach ($designArray as &$singleID)
        {
            $singleID = "'".$singleID."'";
        }
        unset($singleID);
        $designIDs = implode(',', $designArray);

        $sql = "select \"DesignUID\", \"DisplayName\", \"Description\", \"Type\", \"Likes\", \"Comments\", \"PictureUrl\", \"ThumbnailUrl\", \"ViewCount\", \"IsShared\", \"IsCustomisable\", \"CreationDate\", \"ModificationDate\", \"OtherData\", \"ParentUID\", encode(\"Data\", 'base64') from \"Design\" where \"DesignUID\" in ($designIDs) and \"OwnerUID\" = '?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

        $designs = $this->db->sqlToArray($sql);
        if ($designs)
        {
            for ($i=0; $i < count($designs); $i++)
            {
                if ($designs[$i]['Type'] == 2 && !$getDoodlerData)
                {
                    $designs[$i]['encode'] = '';
                }
                if ($this->getCleanValueFromArguments("tData"))
                    $designs[$i]['DesignTags'] = $this->GetDesignTags($designs[$i]['DesignUID'], "true");
                else
                    $designs[$i]['DesignTags'] = $this->GetDesignTags($designs[$i]['DesignUID'], "false");
                $photos = $this->GetDesignPhotos($designs[$i]['DesignUID']);
                if ($photos && $photos != '')
                    $designs[$i]['DesignPhotos'] = $photos;
                $designs[$i]['IsLikedByMe'] = $this->IsDesignLikedByMe($designs[$i]['DesignUID']);
                $designs[$i]['IsFavorited'] = $this->IsDesignFavoritedByMe($designs[$i]['DesignUID']);

                if ($designs[$i]["ParentUID"] == null)
                    $designs[$i]["ParentUID"] = "";
                else if ($designs[$i]["ParentUID"] != "" && $designs[$i]["ParentUID"] != "00000000-0000-0000-0000-000000000000")
                {
                    $parentData = $this->db->fetchArray("select d.\"DisplayName\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\" from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where d.\"DesignUID\" = '" . $designs[$i]["ParentUID"] . "'");
                    if ($parentData)
                    {
                        $designs[$i]["ParentDisplayName"] = $parentData["DisplayName"];
                        $designs[$i]["ParentOwnerUID"] = $parentData["OwnerUID"];
                        $designs[$i]["ParentOwnerName"] = $parentData["OwnerName"];
                    }
                    else
                    {
                        # we didn't find the parent or failed to get the info
                        $designs[$i]["ParentUID"] = "";
                    }
                }
            }

            $arr["designs"] = $designs;
        }

        $arr["result"] = $designs ? 1 : 0;

        return json_encode($arr);
    }

    function GetMissingOwnedDesigns()
    {
        $this->checkUser(true);

        $designIDs = $this->getCleanValueFromArguments('DesignIDs', true);
        $designArray = explode(',', $designIDs);
        foreach ($designArray as &$singleID)
        {
            $singleID = "'".$singleID."'";
        }
        unset($singleID);
        $designIDs = implode(',', $designArray);

        $sql = "select \"DesignUID\", \"DisplayName\", \"Description\", \"Type\", \"Likes\", \"Comments\", \"PictureUrl\", \"ThumbnailUrl\", \"ViewCount\", \"IsShared\", \"IsCustomisable\", \"CreationDate\", \"ModificationDate\", \"ParentUID\" from \"Design\" where \"DesignUID\" in ($designIDs) and \"OwnerUID\" = '?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

        $designs = $this->db->sqlToArray($sql);
        if ($designs)
        {
            for ($i=0; $i < count($designs); $i++)
            {
                if ($this->getCleanValueFromArguments("tData"))
                    $designs[$i]['DesignTags'] = $this->GetDesignTags($designs[$i]['DesignUID'], "true");
                else
                    $designs[$i]['DesignTags'] = $this->GetDesignTags($designs[$i]['DesignUID'], "false");
                $photos = $this->GetDesignPhotos($designs[$i]['DesignUID']);
                if ($photos && $photos != '')
                    $designs[$i]['DesignPhotos'] = $photos;
                $designs[$i]['IsLikedByMe'] = $this->IsDesignLikedByMe($designs[$i]['DesignUID']);
                $designs[$i]['IsFavorited'] = $this->IsDesignFavoritedByMe($designs[$i]['DesignUID']);

                // check if the design is a winner
                $designUID = $designs[$i]["DesignUID"];
                $sql = "select status from competition_submissions where design_id = '$designUID' and status is not null";
                $exists = $this->db->fetchValue($sql);
                if ($exists)
                {
                    $designs[$i]["winner_status"] = $exists;
                }

                if ($designs[$i]["ParentUID"] == null)
                    $designs[$i]["ParentUID"] = "";
                else if ($designs[$i]["ParentUID"] != "" && $designs[$i]["ParentUID"] != "00000000-0000-0000-0000-000000000000")
                {
                    $parentData = $this->db->fetchArray("select d.\"DisplayName\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\" from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where d.\"DesignUID\" = '" . $designs[$i]["ParentUID"] . "'");
                    if ($parentData)
                    {
                        $designs[$i]["ParentDisplayName"] = $parentData["DisplayName"];
                        $designs[$i]["ParentOwnerUID"] = $parentData["OwnerUID"];
                        $designs[$i]["ParentOwnerName"] = $parentData["OwnerName"];
                    }
                    else
                    {
                        # we didn't find the parent or failed to get the info
                        $designs[$i]["ParentUID"] = "";
                    }
                }
            }

            $arr["designs"] = $designs;
        }

        $arr["result"] = $designs ? 1 : 0;

        return json_encode($arr);
    }

    // this function is outdated
    function GetFeaturedLevels()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $limit = 20;

        $sql = "select d.\"DesignUID\", d.\"DisplayName\", d.\"Description\", d.\"Type\", d.\"Likes\", d.\"Comments\", d.\"PictureUrl\", d.\"ThumbnailUrl\", d.\"ViewCount\", d.\"IsCustomisable\", d.\"CreationDate\", d.\"ParentUID\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\", d.\"OtherData\", encode(d.\"Data\", 'base64') from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where d.\"IsShared\" = 't' order by d.\"ViewCount\" desc limit $limit offset 0";

        $designs = $this->db->sqlToArray($sql);
        if ($designs)
        {
            for ($i=0; $i < count($designs); $i++)
            {
                $designs[$i]['DesignTags'] = $this->GetDesignTags($designs[$i]['DesignUID']);
                $photos = $this->GetDesignPhotos($designs[$i]['DesignUID']);
                if ($photos && $photos != '')
                    $designs[$i]['DesignPhotos'] = $photos;
                if ($isUserLoggedIn)
                {
                    $designs[$i]['IsLikedByMe'] = $this->IsDesignLikedByMe($designs[$i]['DesignUID']);
                    $designs[$i]['IsFavorited'] = $this->IsDesignFavoritedByMe($designs[$i]['DesignUID']);
                }
                else
                {
                    $designs[$i]['IsLikedByMe'] = "0";
                    $designs[$i]['IsFavorited'] = "0";
                }

                if ($designs[$i]["ParentUID"] == null)
                    $designs[$i]["ParentUID"] = "";
                else if ($designs[$i]["ParentUID"] != "" && $designs[$i]["ParentUID"] != "00000000-0000-0000-0000-000000000000")
                {
                    $parentData = $this->db->fetchArray("select d.\"DisplayName\", d.\"OwnerUID\", u.\"UserName\" as \"OwnerName\" from \"Design\" d left join \"User\" u on u.\"UserUID\" = d.\"OwnerUID\" where d.\"DesignUID\" = '" . $designs[$i]["ParentUID"] . "'");
                    if ($parentData)
                    {
                        $designs[$i]["ParentDisplayName"] = $parentData["DisplayName"];
                        $designs[$i]["ParentOwnerUID"] = $parentData["OwnerUID"];
                        $designs[$i]["ParentOwnerName"] = $parentData["OwnerName"];
                    }
                    else
                    {
                        # we didn't find the parent or failed to get the info
                        $designs[$i]["ParentUID"] = "";
                    }
                }
            }

            $arr["designs"] = $designs;
        }

        $arr["result"] = $designs ? 1 : 0;

        return json_encode($arr);
    }

    function AddLevel()
    {
        $this->checkUser(true);
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $DisplayName = $this->getCleanValueFromArguments('DisplayName');
        $isShared = $this->getCleanValueFromArguments('IsShared');

        $blocked = $this->db->fetchValue("select count (*) from designs_blocked where design_uid = '$DesignUID'");
        if ($blocked > 0)
        {
            # fail silently (to user) if design is blocked
            $result["result"] = 1;
            $result["DesignUID"] = $DesignUID;
            $result["blocked"] = 1;
            return json_encode($result);
        }

        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count > 0)
        {
            return $this->EditLevel();
        }

        $userSharingPolicy = $this->getCleanValueFromArguments('SharingPolicy');
        if ($userSharingPolicy == '')
        {
            $userSharingPolicy = $this->getUserSharingPolicy(true);
        }

        $appVersionString = $this->db->fetchValue("select app_version_string from \"User\" where \"UserUID\" = $this->currentUserId");

        $ParentUID = $this->getCleanValueFromArguments('ParentUID');
        if ($ParentUID != "")
        {
            $sql = "insert into \"Design\" (\"DesignUID\", \"ParentUID\", \"DisplayName\", \"Type\", \"Description\", \"OtherData\", \"Data\", \"CameraData\", app_version_string, \"OwnerUID\", \"CreationDate\", \"ModificationDate\", \"IsShared\", \"IsCustomisable\", \"SharingPolicy\") values ('?design_Id?', '?parent_Id?', '?display_name?', '?type?', '?description?', '?otherData?', decode('?data?', 'base64'), decode('?cameraData?', 'base64'), '$appVersionString', '?my_Id?', '?creationDate?', '?modificationDate?', '?is_shared?', '?is_customisable?', '?sharing_policy?') ";
            $sql = str_replace("?parent_Id?", $ParentUID, $sql);
        }
        else
            $sql = "insert into \"Design\" (\"DesignUID\", \"DisplayName\", \"Type\", \"Description\", \"OtherData\", \"Data\", \"CameraData\", app_version_string, \"OwnerUID\", \"CreationDate\", \"ModificationDate\", \"IsShared\", \"IsCustomisable\", \"SharingPolicy\") values ('?design_Id?', '?display_name?', '?type?', '?description?', '?otherData?', decode('?data?', 'base64'), decode('?cameraData?', 'base64'), '$appVersionString', '?my_Id?', '?creationDate?', '?modificationDate?', '?is_shared?', '?is_customisable?', '?sharing_policy?') ";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $sql = str_replace("?display_name?", $DisplayName, $sql);
        $sql = str_replace("?description?", $this->getCleanValueFromArguments('Description'), $sql);
        $sql = str_replace("?data?", $this->getCleanValueFromArguments('Data', true), $sql);
        $sql = str_replace("?cameraData?", $this->getCleanValueFromArguments('CameraData'), $sql);
        $sql = str_replace("?otherData?", $this->getCleanValueFromArguments('OtherData'), $sql);

        //$sql = str_replace("?creationDate?", $this->getCleanValueFromArguments('CreationDate'), $sql);
        date_default_timezone_set("UTC");
        $now = new DateTime;
        $nowStr = $now->format('Y-m-d H:i:s');
        $sql = str_replace("?creationDate?", $nowStr, $sql);

        $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);
        $type = $this->getCleanValueFromArguments('Type');
        if ($type == '')
            $type = 0;

        $sql = str_replace("?type?", $type, $sql);
        $sql = str_replace("?is_shared?", $isShared, $sql);
        $sql = str_replace("?is_customisable?", $this->getCleanValueFromArguments('IsCustomisable'), $sql);
        $sql = str_replace("?sharing_policy?", $userSharingPolicy, $sql);

        # create design entry in social db
        $queryResult = $this->db->exesql($sql);
        $querySucceeded = pg_affected_rows($queryResult) > 0;
        if ($querySucceeded)
        {
            # add tags
            $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
            foreach ($tagArray as $singleTag)
            {
                if (trim($singleTag) != '')
                {
                    $this->AddSingleTagToLevel($singleTag, $DesignUID, $isShared);
                }
            }

            $result["PictureUrl"] = '';
            if (count($_FILES) > 0 && $_FILES['SnapshotData']['error'] == 0)
            {
                $fileRelativePath = 'img/design/' . $DesignUID . '.jpg';

                $fileHandler = new FileHandler();
                $result["PictureUrl"] = $fileHandler->moveFile($_FILES['SnapshotData']['tmp_name'], $fileRelativePath);
                if ($result["PictureUrl"] != '')
                {
                    $fileRelativePath = 'img/design/thumbnail/' . $DesignUID . '.jpg';
                    if (isset($_FILES['ThumbnailData']) && is_uploaded_file($_FILES['ThumbnailData']['tmp_name']) && $_FILES['ThumbnailData']['error'] == 0)
                    {
                        $thumbnailUrl = $fileHandler->moveFile($_FILES['ThumbnailData']['tmp_name'], $fileRelativePath);
                    }
                    if ($thumbnailUrl == '')
                    {
                        $thumbnailUrl = $fileHandler->createResizedTexture($result["PictureUrl"], $fileRelativePath, 208);
                    }
                    $result["ThumbnailUrl"] = $thumbnailUrl;

                    // set up for updating picture url and vuforia id
                    $sql = "update \"Design\" set (\"PictureUrl\", \"ThumbnailUrl\", \"AppData\")=('?url?', '?thumbnail_url?', '?v_Id?') where \"DesignUID\"='?design_Id?'";
                    $sql = str_replace("?url?", $result["PictureUrl"], $sql);
                    $sql = str_replace("?design_Id?", $DesignUID, $sql);
                    $sql = str_replace("?thumbnail_url?", $thumbnailUrl, $sql);

                    // upload to vuforia

                    $vuforia = new Vuforia();
                    //$vijson = $vuforia->list_targets();
                    $vijson = $vuforia->add_target($DisplayName, $result["PictureUrl"], $DesignUID);
                    $vi = @json_decode($vijson);
                    if ($vi->result_code == "TargetNameExist")
                    {
                        $result["msg"] = "Vuforia target name exists";
                        $result["msgKey"] = 'ServerMessage78';
                        $sql = str_replace("?v_Id?", "-1", $sql);
                    }
                    else
                    {
                        // store vuforia id so it can be deleted with design
                        $sql = str_replace("?v_Id?", $vi->target_id, $sql);
                        //$sql = str_replace("?v_Id?", $vijson, $sql);
                    }

                    $this->db->exesql($sql);
                }
            }
            else
            {
                $Frame = $this->getCleanValueFromArguments('Frame');
                $CreatePurchaseItem = $this->getCleanValueFromArguments('CreatePurchaseItem') == 'True' ? 't' : 'f';
                $this->InsertDesignIntoRenderQueue($DesignUID, $Frame, 't', $CreatePurchaseItem);
            }

            if (strtolower($isShared) == 'true' && $result["PictureUrl"] != '')
            {
                $userName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\"='$this->currentUserId'");
                $designInfo = $this->db->fetchArray("select \"Description\", \"Type\", \"IsCustomisable\" from \"Design\" where \"DesignUID\"='$DesignUID'");

                // send notification
                $subject = "New design was shared";
                $message = "Application: " . $this->application_name . "<br/>User name: " . $userName . "<br/>User ID: " . $this->currentUserId . "<br/>Design name: " . $DisplayName . "<br/>Design ID: " . $DesignUID;
                if ($designInfo)
                {
                    if ($designInfo['Description'] != '')
                    {
                        $message = $message . "<br/>Design description: " . $designInfo['Description'];
                    }
                    $message = $message . "<br/>Design picture: " . WEBROOT . $result["PictureUrl"];
                    $message = $message . "<br/>Design type: " . $designInfo['Type'];
                    $message = $message . "<br/>Is customisable: " . ($designInfo['IsCustomisable'] == 't' ? 'yes' : 'no');
                }
                $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');
            }
        }
        else
        {
            $result["msg"] = "Unknown error has occurred while adding new design";
            $result["msgKey"] = 'ServerMessage79';
        }

        $result["DesignUID"] = $DesignUID;
        $result["result"] = $querySucceeded ? 1 : 0;

        return json_encode($result);
    }

    function AddTrigger()
    {
        if (!isset($this->arguments["username"]))
        {
            $sql = "select \"UserUID\" from \"User\" where lower(\"Email\")='?email?'";
            $email = strtolower($this->getCleanValueFromArguments("email", true));
            $sql = str_replace("?email?", $email, $sql);
        }
        else
        {
            $sql = "select \"UserUID\" from \"User\" where lower(\"UserName\")='?username?'";
            $username = strtolower($this->getCleanValueFromArguments("username", true));
            $sql = str_replace("?username?", $username, $sql);
        }

        $resultUser = $this->db->fetchArray($sql);
        $this->currentUserId = $resultUser['UserUID'];

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $isShared = $this->getCleanValueFromArguments('IsShared');

        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count > 0)
        {
            return $this->EditLevel();
        }

        $userSharingPolicy = $this->getCleanValueFromArguments('SharingPolicy');
        if ($userSharingPolicy == '')
        {
            $userSharingPolicy = $this->getUserSharingPolicy($this->currentUserId && $this->currentUserId != 0);
        }

        $sql = "insert into \"Design\" (\"DesignUID\", \"DisplayName\", \"Description\", \"OtherData\", \"Data\", \"OwnerUID\", \"CreationDate\", \"ModificationDate\", \"IsShared\", \"IsCustomisable\", \"SharingPolicy\") values ('?design_Id?', '?display_name?', '?description?', '?otherData?', decode('?data?', 'base64'), '?my_Id?', '?creationDate?', '?modificationDate?', '?is_shared?', '?is_customisable?', '?sharing_policy?') ";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $sql = str_replace("?display_name?", $this->getCleanValueFromArguments('DisplayName'), $sql);
        $sql = str_replace("?description?", $this->getCleanValueFromArguments('Description'), $sql);
        $sql = str_replace("?data?", $this->getCleanValueFromArguments('Data', true), $sql);
        $sql = str_replace("?otherData?", $this->getCleanValueFromArguments('OtherData'), $sql);
        $sql = str_replace("?creationDate?", $this->getCleanValueFromArguments('CreationDate'), $sql);
        $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);
        $sql = str_replace("?is_shared?", $isShared, $sql);
        $sql = str_replace("?is_customisable?", $this->getCleanValueFromArguments('IsCustomisable'), $sql);
        $sql = str_replace("?sharing_policy?", $userSharingPolicy, $sql);

        # create design entry in social db
        $queryResult = $this->db->exesql($sql);
        $querySucceeded = pg_affected_rows($queryResult) > 0;
        if ($querySucceeded)
        {
            # add tags
            $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
            foreach ($tagArray as $singleTag)
            {
                if (trim($singleTag) != '')
                {
                    $this->AddSingleTagToLevel($singleTag, $DesignUID, $isShared);
                }
            }
        }
        else
        {
            $result["msg"] = "Unknown error has occurred while adding trigger image";
            $result["msgKey"] = 'ServerMessage80';
        }

        $result["DesignUID"] = $DesignUID;
        $result["result"] = $querySucceeded ? 1 : 0;

        return json_encode($result);
    }


    function SetTriggerImage()
    {
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        // don't do anything if the design was removed in the meantime
        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $this->db->exesql("delete from \"DesignsToRender\" where \"RequestUID\" = '$RequestUID'");
            $arr["result"] = 0;
            return json_encode($arr);
        }

        $pictureRawData = $this->getCleanValueFromArguments('Imagedata', true);

        $currentPictureUrl = $this->db->fetchValue( 'select "PictureUrl" from "Design" where "DesignUID"='."'$DesignUID'" );

        if ($pictureRawData != '')
        {
            $fileHandler = new FileHandler();
            $pictureUrl = $fileHandler->createDesignImageFile($pictureRawData, $DesignUID . '.jpg');
        }
        else
        {
            $pictureUrl = '';
        }

        if ($pictureUrl != '')
        {
            if ($currentPictureUrl != $pictureUrl)
            {
                $sql = "update \"Design\" set \"PictureUrl\" = '$pictureUrl' where \"DesignUID\" = '$DesignUID'";
                $this->db->exesql($sql);

                // remove previous file if it had different name (deprecated naming style)
                if ($currentPictureUrl != '')
                {
                    FileHandler::deleteImageFile($currentPictureUrl);
                }

                $fileRelativePath = 'img/design/thumbnail/' . $DesignUID . '.jpg';
                $thumbnailUrl = $fileHandler->createResizedTexture($pictureUrl, $fileRelativePath, 208);
                if ($thumbnailUrl != '')
                {
                    $currentThumbnailUrl = $this->db->fetchValue("select \"ThumbnailUrl\" from \"Design\" where \"DesignUID\"='$DesignUID'");
                    if ($currentThumbnailUrl != $thumbnailUrl)
                    {
                        $sql = "update \"Design\" set \"ThumbnailUrl\" = '$thumbnailUrl' where \"DesignUID\" = '$DesignUID'";
                        $this->db->exesql($sql);
                    }
                }
            }
        }

        $arr["result"] = $pictureUrl == '' ? 0 : 1;

        return json_encode($arr);
    }    


    function EditLevel()
    {
        $this->checkUser(true);

        // updating design raw data and modification date if set
        $this->UpdateLevelData(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $DisplayName = $this->getCleanValueFromArguments('DisplayName');
        $isShared = $this->getCleanValueFromArguments('IsShared');
        $wasShared = false;

        //clear the display name if user used restricted words
        $ignoreDesignName = false;
        if ($this->ContainsBadWord($DisplayName, "user id - $this->currentUserId tried to rename their design (ID - $DesignUID)", "update \"Design\" set \"DisplayName\" = ''$DisplayName'' where \"DesignUID\" = ''$DesignUID''"))
            $ignoreDesignName = True;

        if (strtolower($isShared) == 'true')
        {
            $sql = "select \"IsShared\" from \"Design\" where \"DesignUID\"='?design_Id?'";
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $wasShared = $this->db->fetchValue($sql) == 't';
        }

        $sql = "";
        if (!isset($this->arguments["Data"]))
        {
            $sql = "select \"OwnerUID\" from \"Design\" where \"DesignUID\" = '?design_Id?'";
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $designOwnerID = $this->db->fetchValue($sql);

            if ($designOwnerID == '' || $designOwnerID == '0')
            {
                // we need to change the owner from one-time user to current user
                if ($ignoreDesignName)
                    $sql = "update \"Design\" set (\"Description\", \"IsShared\", \"IsCustomisable\", \"OwnerUID\") = ('?description?', '?is_shared?', '?is_customisable?', '?my_Id?') where \"DesignUID\" = '?design_Id?' ";
                else
                    $sql = "update \"Design\" set (\"DisplayName\", \"Description\", \"IsShared\", \"IsCustomisable\", \"OwnerUID\") = ('?display_name?', '?description?', '?is_shared?', '?is_customisable?', '?my_Id?') where \"DesignUID\" = '?design_Id?' ";
            }
            else
            {
                if ($designOwnerID == $this->currentUserId)
                {
                    if ($ignoreDesignName)
                        $sql = "update \"Design\" set (\"Description\", \"IsShared\", \"IsCustomisable\") = ('?description?', '?is_shared?', '?is_customisable?') where \"DesignUID\" = '?design_Id?' and \"OwnerUID\" = '?my_Id?' ";
                    else
                        $sql = "update \"Design\" set (\"DisplayName\", \"Description\", \"IsShared\", \"IsCustomisable\") = ('?display_name?', '?description?', '?is_shared?', '?is_customisable?') where \"DesignUID\" = '?design_Id?' and \"OwnerUID\" = '?my_Id?' ";
                }
                else
                {
                    // silently ignore if we are trying to edit another user's design (to avoid popups in app - not sure how the app got into the state of trying to upload other users' designs...)
                    $arr["result"] = 1;
                    return json_encode($arr);
                }
            }
        }
        else
        {
            $sql = "select \"OwnerUID\" from \"Design\" where \"DesignUID\" = '?design_Id?'";
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $designOwnerID = $this->db->fetchValue($sql);

            if ($designOwnerID == $this->currentUserId)
            {
                if ($ignoreDesignName)
                    $sql = "update \"Design\" set (\"Description\", \"IsShared\", \"IsCustomisable\") = ('?description?', '?is_shared?', '?is_customisable?') where \"DesignUID\" = '?design_Id?' and \"OwnerUID\" = '?my_Id?' ";
                else
                    $sql = "update \"Design\" set (\"DisplayName\", \"Description\", \"IsShared\", \"IsCustomisable\") = ('?display_name?', '?description?', '?is_shared?', '?is_customisable?') where \"DesignUID\" = '?design_Id?' and \"OwnerUID\" = '?my_Id?' ";
            }
            else
            {
                // silently ignore if we are trying to edit another user's design (to avoid popups in app - not sure how the app got into the state of trying to upload other users' designs...)
                $arr["result"] = 1;
                return json_encode($arr);
            }
        }

        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        if (!$ignoreDesignName)
            $sql = str_replace("?display_name?", $DisplayName, $sql);
        $sql = str_replace("?description?", $this->getCleanValueFromArguments('Description'), $sql);
        $sql = str_replace("?is_shared?", $isShared, $sql);
        $sql = str_replace("?is_customisable?", $this->getCleanValueFromArguments('IsCustomisable'), $sql);

        # update level entry in db
        $queryResult = $this->db->exesql($sql);
        $querySucceeded = pg_affected_rows($queryResult) > 0;
        $arr["DesignUID"] = $DesignUID;
        if (!$ignoreDesignName)
            $arr["title"] = $DisplayName;
        $arr["result"] = $querySucceeded ? 1 : 0;

        if ($querySucceeded)
        {
            if (!isset($this->arguments["Data"])) // otherwise, already added in UpdateLevelData function
            {
                $Frame = $this->getCleanValueFromArguments('Frame');
                $CreatePurchaseItem = $this->getCleanValueFromArguments('CreatePurchaseItem') == 'True' ? 't' : 'f';
                $this->InsertDesignIntoRenderQueue($DesignUID, $Frame, 't', $CreatePurchaseItem);
            }
            //$designInfo = $this->db->fetchArray("select \"PictureUrl\", \"Description\", \"Type\", \"IsCustomisable\" from \"Design\" where \"DesignUID\"='$DesignUID'");
            //if (strtolower($isShared) == 'true' && !$wasShared && $designInfo && $designInfo['PictureUrl'] != '')
            //{
            //    $userName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\"='$this->currentUserId'");

            //    // send notification
            //    $subject = "Existing design was shared";
            //    $message = "Application: " . $this->application_name . "<br/>User name: " . $userName . "<br/>User ID: " . $this->currentUserId . "<br/>Design name: " . $DisplayName . "<br/>Design ID: " . $DesignUID;
            //    if ($designInfo['Description'] != '')
            //    {
            //        $message = $message . "<br/>Design description: " . $designInfo['Description'];
            //    }
            //    $message = $message . "<br/>Design picture: " . WEBROOT . $designInfo['PictureUrl'];
            //    $message = $message . "<br/>Design type: " . $designInfo['Type'];
            //    $message = $message . "<br/>Is customisable: " . ($designInfo['IsCustomisable'] == 't' ? 'yes' : 'no');

            //    $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');
            //}
        }
        else
        {
            $arr["msg"] = 'Unknown error has occurred while  editing a design';
            $arr["msgKey"] = 'ServerMessage81';
        }

        return json_encode($arr);
    }

    function CreatePurchaseItem()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }
        else
        {
            if (isset($this->arguments["buyerID"]))
            {
                $this->currentUserId = $this->getCleanValueFromArguments('buyerID', true);
            }
            else
            {
                # need to add user to social db
                $username = strtolower('u-'.$this->GUID());
                $array["UserName"] = $username;

                date_default_timezone_set("UTC");
                $array["AccountCreationDate"] =  date("Y-m-d H:i:s", time());

                $token = md5(time());
                $array["AccountToken"] = $token;
                $array["AccountActivated"] = '1';

                $new_id = $this->db->InsertAndReturnNewId("User", $array);

                if (!$new_id || $new_id == 0)
                {
                    $arr["DesignUID"] = $DesignUID;
                    $arr["msg"] = "Failed adding new user";
                    $arr["msgKey"] = 'ServerMessage82';
                    $arr["result"] = 0;
                    return json_encode($arr);
                }
                else
                {
                    // send notification
                    $subject = "New anonymous account was created";
                    $message = "User ID: " . $new_id . "<br/>Design ID: " . $DesignUID;
                    $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');
                }
                $this->currentUserId = $new_id;
            }
        }

        $isOwnedByMe = $this->IsDesignOwnedByMe($DesignUID) > 0;
        $querySucceeded = true;

        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count > 0)
        {
            if ($isOwnedByMe)
            {
                // updating design raw data and modification date
                $this->UpdateLevelData($isUserLoggedIn);
            }
        }
        else
        {
            $userSharingPolicy = $this->getCleanValueFromArguments('SharingPolicy');
            if ($userSharingPolicy == '')
            {
                $userSharingPolicy = $this->getUserSharingPolicy($this->currentUserId && $this->currentUserId != 0);
            }

            $ParentUID = $this->getCleanValueFromArguments('ParentUID');

            // adding new design to db
            if ($ParentUID != "")
            {
                $sql = "insert into \"Design\" (\"DesignUID\", \"ParentUID\", \"DisplayName\", \"Description\", \"OtherData\", \"Data\", \"OwnerUID\", \"CreationDate\", \"ModificationDate\", \"Type\", \"IsShared\", \"IsCustomisable\", \"SharingPolicy\") values ('?design_Id?', '?parent_Id?', '?display_name?', '?description?', '?otherData?', decode('?data?', 'base64'), '?my_Id?', '?creationDate?', '?modificationDate?', '?type?', '?is_shared?', '?is_customisable?', '?sharing_policy?') ";
                $sql = str_replace("?parent_Id?", $ParentUID, $sql);
            }
            else
                $sql = "insert into \"Design\" (\"DesignUID\", \"DisplayName\", \"Description\", \"OtherData\", \"Data\", \"OwnerUID\", \"CreationDate\", \"ModificationDate\", \"Type\", \"IsShared\", \"IsCustomisable\", \"SharingPolicy\") values ('?design_Id?', '?display_name?', '?description?', '?otherData?', decode('?data?', 'base64'), '?my_Id?', '?creationDate?', '?modificationDate?', '?type?', '?is_shared?', '?is_customisable?', '?sharing_policy?') ";
            if ($isUserLoggedIn)
            {
                $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
            }
            else
            {
                $sql = str_replace("?my_Id?", '0', $sql);
            }
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $sql = str_replace("?display_name?", $this->getCleanValueFromArguments('DisplayName'), $sql);
            $sql = str_replace("?description?", $this->getCleanValueFromArguments('Description'), $sql);
            $sql = str_replace("?data?", $this->getCleanValueFromArguments('Data', true), $sql);
            $sql = str_replace("?otherData?", $this->getCleanValueFromArguments('OtherData'), $sql);
            $sql = str_replace("?creationDate?", $this->getCleanValueFromArguments('CreationDate'), $sql);
            $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);
            $type = $this->getCleanValueFromArguments('Type');
            if ($type == '')
                $type = 0;
            $isShared = $this->getCleanValueFromArguments('IsShared');
            if ($isShared == '')
                $isShared = 'False';
            $isCustomisable = $this->getCleanValueFromArguments('IsCustomisable');
            if ($isCustomisable == '')
                $isCustomisable = 'False';
            $sql = str_replace("?type?", $type, $sql);
            $sql = str_replace("?is_shared?", $isShared, $sql);
            $sql = str_replace("?is_customisable?", $isCustomisable, $sql);
            $sql = str_replace("?sharing_policy?", $userSharingPolicy, $sql);

            $queryResult = $this->db->exesql($sql);
            $querySucceeded = pg_affected_rows($queryResult) > 0;
            $isOwnedByMe = true;
        }

        $arr["UserUID"] = $this->currentUserId;
        $arr["DesignUID"] = $DesignUID;
        $arr["PictureUrl"] = '';
        $arr["ThumbnailUrl"] = '';
        $arr["result"] = 1;

        if ($querySucceeded)
        {
            if (!$isOwnedByMe || (isset($this->arguments["SnapshotData"]) || (count($_FILES) > 0 && $_FILES['SnapshotData']['error'] == 0)))
            {
                if($isOwnedByMe)
                {
                    $fileHandler = new FileHandler();
                    $fileRelativePath = 'img/design/' . $DesignUID . '.jpg';

                    if (isset($this->arguments["SnapshotData"])) // for backward compatibility
                    {
                        $LevelPictureRawData = $this->getCleanValueFromArguments('SnapshotData');
                        $pictureUrl = $fileHandler->createDesignImageFile($LevelPictureRawData, $DesignUID . '.jpg');
                    }
                    else
                    {
                        $pictureUrl = $fileHandler->moveFile($_FILES['SnapshotData']['tmp_name'], $fileRelativePath);
                    }

                    if ($pictureUrl != '')
                    {
                        $currentPictureUrl = $this->db->fetchValue("select \"PictureUrl\" from \"Design\" where \"DesignUID\"='$DesignUID'");
                        if ($currentPictureUrl != $pictureUrl)
                        {
                            $sql = "update \"Design\" set \"PictureUrl\" = '$pictureUrl' where \"DesignUID\" = '$DesignUID'";
                            $this->db->exesql($sql);

                            // remove previous file if it had different name (deprecated naming style)
                            if ($currentPictureUrl != '')
                            {
                                FileHandler::deleteImageFile($currentPictureUrl);
                            }
                            else
                            {
                                # image set for the first time so we're sending a notification if the design is shared
                                $designInfo = $this->db->fetchArray("select \"IsShared\", \"Description\", \"DisplayName\", \"Type\", \"IsCustomisable\" from \"Design\" where \"DesignUID\"='$DesignUID'");
                                if ($designInfo && $designInfo['IsShared'] == 't')
                                {
                                    $userName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\"='$this->currentUserId'");

                                    // send notification
                                    $subject = ($count > 0 ? "Existing" : "New") . " design was shared";
                                    $message = "Application: " . $this->application_name . "<br/>User name: " . $userName . "<br/>User ID: " . $this->currentUserId . "<br/>Design name: " . $designInfo['DisplayName'] . "<br/>Design ID: " . $DesignUID;
                                    if ($designInfo['Description'] != '')
                                    {
                                        $message = $message . "<br/>Design description: " . $designInfo['Description'];
                                    }
                                    $message = $message . "<br/>Design picture: " . WEBROOT . $pictureUrl;
                                    $message = $message . "<br/>Design type: " . $designInfo['Type'];
                                    $message = $message . "<br/>Is customisable: " . ($designInfo['IsCustomisable'] == 't' ? 'yes' : 'no');

                                    $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');
                                }
                            }
                        }
                        $arr["PictureUrl"] = $pictureUrl;

                        $fileRelativePath = 'img/design/thumbnail/' . $DesignUID . '.jpg';
                        if (isset($_FILES['ThumbnailData']) && is_uploaded_file($_FILES['ThumbnailData']['tmp_name']) && $_FILES['ThumbnailData']['error'] == 0)
                        {
                            $thumbnailUrl = $fileHandler->moveFile($_FILES['ThumbnailData']['tmp_name'], $fileRelativePath);
                        }
                        if ($thumbnailUrl == '')
                        {
                            $thumbnailUrl = $fileHandler->createResizedTexture($pictureUrl, $fileRelativePath, 208);
                        }
                        if ($thumbnailUrl != '')
                        {
                            $currentThumbnailUrl = $this->db->fetchValue("select \"ThumbnailUrl\" from \"Design\" where \"DesignUID\"='$DesignUID'");
                            if ($currentThumbnailUrl != $thumbnailUrl)
                            {
                                $sql = "update \"Design\" set \"ThumbnailUrl\" = '$thumbnailUrl' where \"DesignUID\" = '$DesignUID'";
                                $this->db->exesql($sql);

                                #// remove previous file if it had different name
                                #if ($currentThumbnailUrl != '')
                                #{
                                #    FileHandler::deleteImageFile($currentThumbnailUrl);
                                #}
                            }
                            $arr["ThumbnailUrl"] = $thumbnailUrl;
                        }
                    }
                }

                //$sql = "insert into \"Product\" (\"DesignUID\", \"OwnerUID\", \"Width\") values ('?designUID?', '?ownerUID?', '?width?') returning \"ProductUID\"";
                $sql = "insert into \"Product\" (\"OwnerUID\") values ('?ownerUID?') returning \"ProductUID\"";
                $sql = str_replace("?ownerUID?", $this->currentUserId, $sql);
                //$sql = str_replace("?designUID?", $DesignUID, $sql);
                $productIndex = $this->db->fetchValue($sql);
                if ($productIndex)
                {
                    $deckID = $this->getCleanValueFromArguments('deckID', true);
                    $trucksID = $this->getCleanValueFromArguments('trucksID', true);
                    $wheelsID = $this->getCleanValueFromArguments('wheelsID', true);
                    $shipmentID = $this->getCleanValueFromArguments('shipmentID', true);

                    if ((int)$deckID > 0 && (int)$shipmentID > 0)
                    {
                        $sql = "select \"Name\", \"Price\" from \"Prices\" where \"PriceUID\"='?price_Id?'";
                        $sql = str_replace("?price_Id?", $deckID, $sql);
                        $deckInfo = $this->db->fetchArray($sql);
                        $sql = "select \"Price\" from \"Prices\" where \"PriceUID\"='?price_Id?'";
                        $sql = str_replace("?price_Id?", $shipmentID, $sql);
                        $shipmentCosts = $this->db->fetchValue($sql);

                        if ($deckInfo && $shipmentCosts > 0)
                        {
                            $itemsToBuy = array();
                            $arrayItem = array(
                                "name" => 'Deck: ' . $deckInfo['Name'],
                                "price" => (int)$deckInfo['Price'],
                            );
                            $itemsToBuy[] = $arrayItem;

                            if ((int)$trucksID > 0)
                            {
                                $sql = "select \"Name\", \"Price\" from \"Prices\" where \"PriceUID\"='?price_Id?'";
                                $sql = str_replace("?price_Id?", $trucksID, $sql);
                                $trucksInfo = $this->db->fetchArray($sql);

                                if ($trucksInfo)
                                {
                                    $arrayItem = array(
                                        "name" => 'Trucks: ' . $trucksInfo['Name'],
                                        "price" => (int)$trucksInfo['Price'],
                                    );
                                    $itemsToBuy[] = $arrayItem;
                                }
                            }
                            if ((int)$wheelsID > 0)
                            {
                                $sql = "select \"Name\", \"Price\" from \"Prices\" where \"PriceUID\"='?price_Id?'";
                                $sql = str_replace("?price_Id?", $wheelsID, $sql);
                                $wheelsInfo = $this->db->fetchArray($sql);

                                if ($wheelsInfo)
                                {
                                    $arrayItem = array(
                                        "name" => 'Wheels: ' . $wheelsInfo['Name'],
                                        "price" => (int)$wheelsInfo['Price'],
                                    );
                                    $itemsToBuy[] = $arrayItem;
                                }
                            }

                            $this->db->exesql("update \"Product\" set (\"DeckID\", \"ShipmentID\", \"TrucksID\", \"WheelsID\") = ($deckID, $shipmentID, $trucksID, $wheelsID) where \"ProductUID\" = $productIndex");

                            $arr["ProductUID"] = $productIndex;
                            $arr["shipmentCosts"] = (int)$shipmentCosts;
                            $arr["itemsToBuy"] = $itemsToBuy;
                            $arr["ProductUrl"] = PayPalHandler::GeneratePaymentLink($productIndex, $shipmentCosts, $itemsToBuy);
                        }
                        else
                        {
                            $arr["msg"] = "Failed adding new product - there are no items to buy";
                            $arr["msgKey"] = 'ServerMessage83';
                            $arr["result"] = 0;
                        }
                    }
                    else
                    {
                        $arr["msg"] = "Failed adding new product - there are no items to buy";
                        $arr["msgKey"] = 'ServerMessage83';
                        $arr["result"] = 0;
                    }

                    if ($arr["result"] == 0)
                    {
                        $this->db->exesql("delete from \"Product\" where \"ProductUID\" = $productIndex");
                    }
                }
                else
                {
                    $arr["msg"] = "Failed adding new product";
                    $arr["msgKey"] = 'ServerMessage84';
                    $arr["result"] = 0;
                }
            }
            else
            {
                $arr["msg"] = "Image data not found";
                $arr["msgKey"] = 'ServerMessage85';
                $arr["result"] = 0;
            }
        }
        else
        {
            $arr["msg"] = "Failed adding new design";
            $arr["msgKey"] = 'ServerMessage86';
            $arr["result"] = 0;
        }

        return json_encode($arr);
    }
    
    function EditTags()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $isShared = $this->getCleanValueFromArguments('IsShared');

        # remove old tags from level
        $this->db->exesql("delete from \"DesignTag\" where \"DesignUID\"='$DesignUID'");

        # add new tags to level
        $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
        foreach ($tagArray as $singleTag)
        {
            if (trim($singleTag) != '')
            {
                $this->AddSingleTagToLevel($singleTag, $DesignUID, $isShared);
            }
        }

        $arr["DesignUID"] = $DesignUID;
        $arr["result"] = 1;
        
        return json_encode($arr);
    }

    function AddOrRemoveTags()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $isShared = $this->getCleanValueFromArguments('IsShared');
        $adding = $this->getCleanValueFromArguments("Adding");

        $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));

        foreach ($tagArray as $singleTag)
        {
            if (trim($singleTag) != '')
            {
                if ($this->ContainsBadWord($singleTag, "user id - $this->currentUserId tried adding a tag to design with ID - $DesignUID", "insert into \"DesignTag\" (\"DesignUID\", \"TagText\") values (''$DesignUID'', ''$singleTag'')"))
                    continue;

                if ($adding == "True")
                {
                    $this->AddSingleTagToLevel($singleTag, $DesignUID, $isShared, $this->currentUserId);
                }
                else
                {
                    $this->db->exesql("delete from \"DesignTag\" where \"DesignUID\" = '$DesignUID' and \"TagText\" = '$singleTag'");
                }
            }
        }

        $arr["DesignUID"] = $DesignUID;
        $arr["result"] = 1;

        return json_encode($arr);
    }

    function UpdateLevelData($checkUser = true)
    {
        if ($checkUser)
        {
            $this->checkUser(true);
        }

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        if (isset($this->arguments["Data"]))
        {
            $data = $this->getCleanValueFromArguments('Data');
            $otherData = $this->getCleanValueFromArguments('OtherData');

            // hack to avoid data loss - we shouldn't be calling UpdateLevelData if the data is empty
            if ($data == "" && $otherData == "")
            {
                $arr["result"] = 1;
                $arr["DesignUID"] = $DesignUID;
//                $arr["msg"] = "Missing design data";
//                $arr["msgKey"] = 'ServerMessage87';
                return json_encode($arr);
            }

            $sql = "select \"OwnerUID\" from \"Design\" where \"DesignUID\" = '?design_Id?'";
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $designOwnerID = $this->db->fetchValue($sql);

            $appVersionString = $this->db->fetchValue("select app_version_string from \"User\" where \"UserUID\" = $this->currentUserId");

            if ($designOwnerID == '' || $designOwnerID == '0')
            {
                if ($checkUser)
                {
                    // user is logged in so we need to change the owner from one-time user to current user
                    $sql = "update \"Design\" set (\"ModificationDate\", \"OwnerUID\", \"OtherData\", \"Data\", \"CameraData\", app_version_string) = ('?modificationDate?', '?my_Id?', '?otherData?', decode('?data?', 'base64'), decode('?cameraData?', 'base64'), '$appVersionString') where \"DesignUID\" = '?design_Id?'";
                    $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
                }
                else
                {
                    $sql = "update \"Design\" set (\"ModificationDate\", \"OtherData\", \"Data\", \"CameraData\", app_version_string) = ('?modificationDate?', '?otherData?', decode('?data?', 'base64'), decode('?cameraData?', 'base64'), '$appVersionString') where \"DesignUID\" = '?design_Id?'";
                }
            }
            else
            {
                $sql = "update \"Design\" set (\"ModificationDate\", \"OtherData\", \"Data\", \"CameraData\", app_version_string) = ('?modificationDate?', '?otherData?', decode('?data?', 'base64'), decode('?cameraData?', 'base64'), '$appVersionString') where \"DesignUID\" = '?design_Id?' and \"OwnerUID\" = '?my_Id?'";
                $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
            }

            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $sql = str_replace("?otherData?", $this->getCleanValueFromArguments('OtherData'), $sql);
            $sql = str_replace("?data?", $this->getCleanValueFromArguments('Data'), $sql);
            $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);

            $cameraData = $this->getCleanValueFromArguments('CameraData');
            if ($cameraData == '')
                $sql = str_replace("?cameraData?", null, $sql);
            else
                $sql = str_replace("?cameraData?", $cameraData, $sql);


            $queryResult = $this->db->exesql($sql);
            $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
            $arr["DesignUID"] = $DesignUID;

            if (isset($this->arguments["Frame"]))
            {
                $folderName = substr($DesignUID, 0, 2);
                $fullPath = "/var/www/html/picto/stl/$folderName/$DesignUID" . ".stl";
                $fileExists = file_exists($fullPath);
                if ($fileExists)
                {
                    // delete the existing stl
                    unlink($fullPath);
                }

                $Frame = $this->getCleanValueFromArguments('Frame');
                $CreatePurchaseItem = $this->getCleanValueFromArguments('CreatePurchaseItem') == 'True' ? 't' : 'f';
                $this->InsertDesignIntoRenderQueue($DesignUID, $Frame, 't', $CreatePurchaseItem);
            }
        }
        else
        {
            $arr["result"] = 0;
            $arr["DesignUID"] = $DesignUID;
            $arr["msg"] = "Missing design data";
            $arr["msgKey"] = 'ServerMessage87';
        }

        return json_encode($arr);
    }

    function UpdateModelColors()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $ModificationDate = $this->getCleanValueFromArguments('ModificationDate');

        if ($ModificationDate != "")
        {
            $sql = "update \"Design\" set (\"ModificationDate\", \"ColorWheels\", \"ColorBearings\", \"ColorTrucks\", \"ColorBushings\", \"ColorBase\") = ('?modificationDate?', '?colorWheels?', '?colorBearings?', '?colorTrucks?', '?colorBushings?', '?colorBase?') where \"DesignUID\" = '?design_Id?' and \"OwnerUID\" = '?my_Id?' ";
            $sql = str_replace("?modificationDate?", $ModificationDate, $sql);
        }
        else
        {
            $sql = "update \"Design\" set (\"ColorWheels\", \"ColorBearings\", \"ColorTrucks\", \"ColorBushings\", \"ColorBase\") = ('?colorWheels?', '?colorBearings?', '?colorTrucks?', '?colorBushings?', '?colorBase?') where \"DesignUID\" = '?design_Id?' and \"OwnerUID\" = '?my_Id?' ";
        }
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?colorWheels?", $this->getCleanValueFromArguments('ColorWheels'), $sql);
        $sql = str_replace("?colorBearings?", $this->getCleanValueFromArguments('ColorBearings'), $sql);
        $sql = str_replace("?colorTrucks?", $this->getCleanValueFromArguments('ColorTrucks'), $sql);
        $sql = str_replace("?colorBushings?", $this->getCleanValueFromArguments('ColorBushings'), $sql);
        $sql = str_replace("?colorBase?", $this->getCleanValueFromArguments('ColorBase'), $sql);

        # update level entry in db
        $arr["DesignUID"] = $DesignUID;
        $queryResult = $this->db->exesql($sql);
        $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;

        return json_encode($arr);
    }

    function DeleteLevel()
    {
        $this->checkUser(true);
        $DesignUID = $this->getCleanValueFromArguments('LevelUID', true);

        $designData = $this->db->fetchArray("select \"ParentUID\", \"PictureUrl\", \"ThumbnailUrl\", makerbot_id from \"Design\" where \"DesignUID\"='$DesignUID'");
        if ($designData)
        {
            $parentUID = $designData["ParentUID"];
            if ($parentUID == null || $parentUID == "")
                $parentUID = "00000000-0000-0000-0000-000000000000";
            $levelPictureUrl = $designData["PictureUrl"];
            $levelThumbnailUrl = $designData["ThumbnailUrl"];
            $vuforiaId = NULL; //$designData["AppData"];
            $makerbot_id = $designData["makerbot_id"];
        }
        else
        {
            $parentUID = "00000000-0000-0000-0000-000000000000";
            $levelPictureUrl = "";
            $levelThumbnailUrl = "";
            $vuforiaId = "";
            $makerbot_id = 0;
        }

        $sql = "delete from \"Design\" where \"DesignUID\"='?level_Id?' and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?level_Id?", $DesignUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

        # delete from social db
        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) > 0)
        {
            $arr["result"] = 1;

            # remove design's picture
            if ($levelPictureUrl != '')
            {
                FileHandler::deleteImageFile($levelPictureUrl);
            }
            # and thumbnail
            if ($levelThumbnailUrl != '')
            {
                FileHandler::deleteImageFile($levelThumbnailUrl);
            }

            # remove from render list
            $this->db->exesql("delete from \"DesignsToRender\" where \"DesignUID\"='$DesignUID'");

            # remove from favorites
            $this->db->exesql("delete from \"Favorite\" where \"DesignUID\"='$DesignUID'");

            # remove from liked
            $this->db->exesql("delete from \"Like\" where \"DesignUID\"='$DesignUID'");

            # remove design tags
            $this->db->exesql("delete from \"DesignTag\" where \"DesignUID\"='$DesignUID'");

            # remove design comments
            $comments = $this->db->exesqlAndReturnArray("select \"CommentUID\" from \"Comment\" where \"DesignUID\"='$DesignUID'");
            if ($comments)
            {
                $idString = implode(',', $comments);
                $this->db->exesql("delete from \"CommentRating\" where \"CommentUID\" in ($idString)");
                $this->db->exesql("delete from \"Comment\" where \"CommentUID\" in ($idString)");
            }

            # delete vuforia target
            if ($vuforiaId != NULL && $vuforiaId != "")
            {
                $vuforia = new Vuforia();
                $vuforia->delete_target($vuforiaId);
            }

            # remove all photos and their thumbnails
            $photos = $this->db->sqlToArray("select \"PhotoUrl\", \"ThumbnailUrl\" from \"DesignPhotos\" where \"DesignUID\"='$DesignUID'");
            $this->db->exesql("delete from \"DesignPhotos\" where \"DesignUID\"='$DesignUID'");
            if ($photos)
            {
                for ($i=0; $i < count($photos); $i++)
                {
                    # remove photo
                    if ($photos[$i]['PhotoUrl'] != '')
                    {
                        FileHandler::deleteImageFile($photos[$i]['PhotoUrl']);
                    }
                    # and thumbnail
                    if ($photos[$i]['ThumbnailUrl'] != '')
                    {
                        FileHandler::deleteImageFile($photos[$i]['ThumbnailUrl']);
                    }
                }
            }

            # remove design from makerbot library
            $makerbot_token = $this->db->fetchValue("select makerbot_token from \"User\" where \"UserUID\"='$this->currentUserId'");
            if ($makerbot_id != null && $makerbot_id != 0 && $makerbot_token != null)
            {
                $thingiverse = new Thingiverse($makerbot_token);
                $response = $thingiverse->deleteThing($makerbot_id);
                error_log('Delete id ' . $makerbot_id . ' response ' . $response);
            }

            // delete entries this design may have had in any competitions
            $this->db->exesql("delete from competition_submissions where design_id = '$DesignUID'");

            # reparent customised designs
            $this->db->exesql("update \"Design\" set \"ParentUID\" = '$parentUID' where \"ParentUID\" = '$DesignUID'");
        }
        else
        {
            $arr["result"] = 0;
        }
        $arr["LevelUID"] = $DesignUID;

        return json_encode($arr);
    }

    function FavoriteDesign()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        // don't do anything if the design was removed in the meantime
        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            die($this->JsonError("Design was not found in the database", 'ServerMessage26'));
        }

        $arr["DesignUID"] = $DesignUID;
        $arr["result"] = 1;

        if($this->IsDesignFavoritedByMe($DesignUID) == 0)
        {
            $sql = "insert into \"Favorite\" (\"DesignUID\", \"UserUID\") values ('?design_Id?', '?my_Id?')";
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
        }

        return json_encode($arr);
    }

    function UnfavoriteDesign()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        $arr["DesignUID"] = $DesignUID;
        $arr["result"] = 1;

        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count > 0)
        {
            $sql = "delete from \"Favorite\" where \"DesignUID\"='?design_Id?' and \"UserUID\"='?my_Id?'";
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
        }

        return json_encode($arr);
    }

    private function checkLevelOwner($userId, $levelId)
    {
        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?level_Id?' and \"OwnerUID\"=?user_Id?";
        $sql = str_replace("?user_Id?", $userId, $sql);
        $sql = str_replace("?level_Id?", $levelId, $sql);

        $count = $this->db->fetchValue($sql);

        if($count != 1)
        {
            die($this->JsonError("You are not the owner of that design", 'ServerMessage27'));
        }
    }
    
    function SetDesignCover()
    {
        $RequestUID = $this->getCleanValueFromArguments('RequestUID', true);
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        // don't do anything if the cover request is outdated (there was another request in the meantime)
        $sql = "select count(\"RequestUID\") as final_count from \"DesignsToRender\" where \"RequestUID\"='?request_Id?'";
        $sql = str_replace("?request_Id?", $RequestUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["result"] = 0;
            return json_encode($arr);
        }

        // don't do anything if the design was removed in the meantime
        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $this->db->exesql("delete from \"DesignsToRender\" where \"RequestUID\" = '$RequestUID'");
            $arr["result"] = 0;
            return json_encode($arr);
        }

        $currentPictureUrl = $this->db->fetchValue( 'select "PictureUrl" from "Design" where "DesignUID"='."'$DesignUID'" );

        if (count($_FILES) > 0 && $_FILES['SnapshotData']['error'] == 0)
        {
            $fileHandler = new FileHandler();

            $fileRelativePath = 'img/design/' . $DesignUID . '.jpg';

            $pictureUrl = $fileHandler->moveFile($_FILES['SnapshotData']['tmp_name'], $fileRelativePath);
            if ($pictureUrl != '')
            {
                $fileRelativePath = 'img/design/thumbnail/' . $DesignUID . '.jpg';
                if (isset($_FILES['ThumbnailData']) && is_uploaded_file($_FILES['ThumbnailData']['tmp_name']) && $_FILES['ThumbnailData']['error'] == 0)
                {
                    $thumbnailUrl = $fileHandler->moveFile($_FILES['ThumbnailData']['tmp_name'], $fileRelativePath);
                }
                if ($thumbnailUrl == '')
                {
                    $thumbnailUrl = $fileHandler->createResizedTexture($pictureUrl, $fileRelativePath, 256);
                }

                $smallerThumbnailPath = 'img/design/thumbnail/' . $DesignUID . '-190x190.jpg';
                $fileHandler->createResizedTexture($pictureUrl, $smallerThumbnailPath, 190);

                $currentThumbnailUrl = $this->db->fetchValue( 'select "ThumbnailUrl" from "Design" where "DesignUID"='."'$DesignUID'" );
                if ($thumbnailUrl != '' && $currentThumbnailUrl != $thumbnailUrl)
                {
                    $sql = "update \"Design\" set \"ThumbnailUrl\" = '$thumbnailUrl' where \"DesignUID\" = '$DesignUID'";
                    $this->db->exesql($sql);

                    // remove previous file if it had different name
                    if ($currentThumbnailUrl != '')
                    {
                        FileHandler::deleteImageFile($currentThumbnailUrl);
                    }
                }

                if ($thumbnailUrl != '')
                {
                    $run = exec('convert '.$thumbnailUrl.' '.'img/design/thumbnail/' . $DesignUID . '.jpg',$out,$err);
                }

                $run = exec('convert '.$pictureUrl.' '.'img/design/' . $DesignUID . '.jpg',$out,$err);
            }
            else
            {
                $arr["msg"] = "Failed to save snapshot file";
                $arr["msgKey"] = 'ServerMessage88';
            }
        }
        else
        {
            $pictureUrl = '';
            $arr["msg"] = "Failed to upload snapshot file";
            $arr["msgKey"] = 'ServerMessage89';
        }

        if ($pictureUrl != '')
        {
            if ($currentPictureUrl != $pictureUrl)
            {
                $sql = "update \"Design\" set \"PictureUrl\" = '$pictureUrl' where \"DesignUID\" = '$DesignUID'";
                $this->db->exesql($sql);

                // remove previous file if it had different name (deprecated naming style)
                if ($currentPictureUrl != '')
                {
                    FileHandler::deleteImageFile($currentPictureUrl);
                }
                else
                {
                    # image set for the first time so we're sending a notification if the design is shared
                    $designInfo = $this->db->fetchArray("select \"IsShared\", \"OwnerUID\", \"Description\", \"DisplayName\", \"Type\", \"IsCustomisable\" from \"Design\" where \"DesignUID\"='$DesignUID'");
                    if ($designInfo && $designInfo['IsShared'] == 't')
                    {
                        $userName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\"=".$designInfo['OwnerUID']);

                        // send notification
                        $subject = "A design was shared";
                        $message = "Application: " . $this->application_name . "<br/>User name: " . $userName . "<br/>User ID: " . $designInfo['OwnerUID'] . "<br/>Design name: " . $designInfo['DisplayName'] . "<br/>Design ID: " . $DesignUID;
                        if ($designInfo['Description'] != '')
                        {
                            $message = $message . "<br/>Design description: " . $designInfo['Description'];
                        }
                        $message = $message . "<br/>Design picture: " . WEBROOT . $pictureUrl;
                        $message = $message . "<br/>Design type: " . $designInfo['Type'];
                        $message = $message . "<br/>Is customisable: " . ($designInfo['IsCustomisable'] == 't' ? 'yes' : 'no');

                        $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');
                    }
                }
            }

            $this->db->exesql("delete from \"DesignsToRender\" where \"RequestUID\" = '$RequestUID'");
        }
        else
        {
            // mark the request as not processed to retry
            $sql = "update \"DesignsToRender\" set \"ProcessingTimeLimit\" = LOCALTIMESTAMP - interval '1 hour' where \"RequestUID\"='?request_Id?'";
            $sql = str_replace("?request_Id?", $RequestUID, $sql);
            $this->db->exesql($sql);
        }

        $arr["result"] = $pictureUrl == '' ? 0 : 1;

        return json_encode($arr);
    }

    function AddDesignPhoto()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $arr["DesignUID"] = $DesignUID;

        // don't do anything if the design was removed in the meantime
        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["result"] = 0;
            $arr["msg"] = "Selected design is no longer available";
            $arr["msgKey"] = 'ServerMessage90';
            return json_encode($arr);
        }

        if (count($_FILES) > 0 && $_FILES['PhotoData']['error'] == 0)
        {
            $fileHandler = new FileHandler();

            $fileBaseName = $DesignUID . '-' . time();
            $fileRelativePath = 'img/design/photo/' . $fileBaseName . '.jpg';
            $counter = 0;
            while (file_exists(FileHandler::path . $fileRelativePath))
            {
                $counter++;
                $fileBaseName = $DesignUID . '-' . (time() - $counter);
                $fileRelativePath = 'img/design/photo/' . $fileBaseName . '.jpg';
            }

            $pictureUrl = $fileHandler->moveFile($_FILES['PhotoData']['tmp_name'], $fileRelativePath);
            if ($pictureUrl != '')
            {
                $thumbnailUrl = '';
                $fileRelativePath = 'img/design/photo/' . $fileBaseName . '_thumb.jpg';
                if (isset($_FILES['ThumbnailData']) && is_uploaded_file($_FILES['ThumbnailData']['tmp_name']) && $_FILES['ThumbnailData']['error'] == 0)
                {
                    $thumbnailUrl = $fileHandler->moveFile($_FILES['ThumbnailData']['tmp_name'], $fileRelativePath);
                }
                if ($thumbnailUrl == '')
                {
                    $thumbnailUrl = $fileHandler->createResizedTexture($pictureUrl, $fileRelativePath, 128);
                }

                //if ($thumbnailUrl != '')
                //{
                //    $run = exec('convert '.$thumbnailUrl.' '.'img/design/photo/' . $DesignUID . '_thumb.jpg',$out,$err);
                //    FileHandler::deleteImageFile($thumbnailUrl);
                //    $thumbnailUrl = rtrim($thumbnailUrl, "png") . "jpg";
                //}

                //$run = exec('convert '.$pictureUrl.' '.'img/design/photo/' . $DesignUID . '.jpg',$out,$err);
                //FileHandler::deleteImageFile($pictureUrl);
                //$pictureUrl = rtrim($pictureUrl, "png") . "jpg";
            }
            else
            {
                $arr["msg"] = "Failed to save design photo";
                $arr["msgKey"] = 'ServerMessage91';
            }
        }
        else
        {
            $pictureUrl = '';
            $arr["msg"] = "Failed to upload design photo";
            $arr["msgKey"] = 'ServerMessage92';
        }

        if ($pictureUrl != '')
        {
            $designInfo = $this->db->fetchArray("select \"OwnerUID\", \"Description\", \"DisplayName\", \"Type\", \"IsCustomisable\", \"PictureUrl\" from \"Design\" where \"DesignUID\"='$DesignUID'");
            $isAccepted = 'f'; //$designInfo && $designInfo['OwnerUID'] == $this->currentUserId ? 't' : 'f';
            $approvalToken = md5(time());
            $sql = "insert into \"DesignPhotos\" (\"DesignUID\", \"UserUID\", \"PhotoUrl\", \"ThumbnailUrl\", \"IsAccepted\", \"ApprovalToken\") values ('$DesignUID', '$this->currentUserId', '$pictureUrl', '$thumbnailUrl', '$isAccepted', '$approvalToken') returning \"DesignPhotoUID\"";
            $newID = $this->db->fetchValue($sql);

            if ($newID)
            {
                $arr["DesignPhotoUID"] = $newID;
                $arr["UserUID"] = $this->currentUserId;
                $arr["PhotoUrl"] = $pictureUrl;
                $arr["ThumbnailUrl"] = $thumbnailUrl;
                $arr["IsAccepted"] = $isAccepted;

                # send a notification if the photo was added by a user that is not an owner of the design
                if ($designInfo)
                {
                    $userName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\" = '$this->currentUserId'");
                    $authorInfo = $this->db->fetchArray("select \"Email\", \"UserName\", \"UnlockCode\" from \"User\" where \"UserUID\" = '" . $designInfo['OwnerUID'] . "'");
                    $photoLink = WEBROOT . $pictureUrl;
                    $url = WEBROOT . "action/approve_reject_photo.php?photo=$newID&token=$approvalToken&action=";

                    // notification for the Support
                    $subject = "New photo has been added to a design";
                    $message = "Application: " . $this->application_name . "<br/>Author name: " . $authorInfo["UserName"] . "<br/>Author ID: " . $designInfo['OwnerUID'] . "<br/>Design name: " . $designInfo['DisplayName'] . "<br/>Design ID: " . $DesignUID;
                    if ($designInfo['Description'] != '')
                    {
                        $message = $message . "<br/>Design description: " . $designInfo['Description'];
                    }
                    if ($designInfo['PictureUrl'] != '')
                    {
                        $message = $message . "<br/>Design picture: <a href=\"" . WEBROOT . $designInfo['PictureUrl'] . "\">" . WEBROOT . $designInfo['PictureUrl'] . "</a>";
                    }
                    $message = $message . "<br/>Design type: " . $designInfo['Type'];
                    $message = $message . "<br/>Is customisable: " . ($designInfo['IsCustomisable'] == 't' ? 'yes' : 'no');
                    $message = $message . "<br/><br/>Uploader name: " . $userName;
                    $message = $message . "<br/>Uploader ID: " . $this->currentUserId;
                    $message = $message . "<br/>New photo: <a href=\"" . $photoLink . "\">" . $photoLink . "</a>";

                    $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');

                    // send photo approval request
                    if ($authorInfo['UnlockCode'] == 0)
                    {
                        $approvalEmail = $this->info_email_address;
                    }
                    else
                    {
                        $approvalEmail = $this->db->fetchValue("select \"ApprovalEmail\" from \"UnlockCodes\" where codeuid = " . $authorInfo['UnlockCode']);
                        if (!$approvalEmail || $approvalEmail == '')
                            $approvalEmail = $this->info_email_address;
                    }

                    $designName = $designInfo['DisplayName'];
                    if ($designName == NULL || $designName == false || $designName == '')
                    {
                        $designName = "untitled design";
                    }
                    //else
                    //{
                    //    $designName = "design '$designName'";
                    //}

                    //$approve = "<a href=\"" . $url . '1' . "\">approve</a>";
                    //$reject = "<a href=\"" . $url . '0' . "\">reject</a>";
                    $approve = $url . '1';
                    $reject = $url . '0';

                    $subject = "New photo is waiting for approval";
                    //$message = "Hello,";
                    //$message = $message . "<br/><br/>A photo has been added to $designName by $userName. Please $approve or $reject.";
                    //$message = $message . "<br/><a href=\"" . $photoLink . "\">" . $photoLink . "</a>";
                    //$message = $message . "<br/><img src=\"" . $photoLink . "\" alt=\"new photo\" />";
                    $designPictureUrl = WEBROOT . $designInfo['PictureUrl'];
                    $globalMergeVars = array(
	 	        array('name' => 'USERNAME', 'content' => $userName),
    	                array('name' => 'DESIGNNAME', 'content' => $designName),
                        array('name' => 'URL', 'content' => $photoLink),
                        array('name' => 'DESIGNURL', 'content' => $designPictureUrl),
    		        array('name' => 'APPROVE', 'content' => $approve),
		        array('name' => 'REJECT', 'content' => $reject)
	    	    );
                    $this->SendEmailMandrill("photo-approval", $globalMergeVars, $approvalEmail, $subject, $this->info_email_address, $this->application_name, "false");
                    //if ($approvalEmail == $this->info_email_address)
                    //{
                        //if ($authorInfo['UnlockCode'] == 0)
                            //$message = $message . "<br/><br/>The design owner is not a student.";
                        //else
                            //$message = $message . "<br/><br/>The school " . $authorInfo['UnlockCode'] . " doesn't have a person responsible for photo approval.";
                    //}
                    //else
                    //{
                        //$message = $message . "<br/><br/>Thanks,<br/>Makers Empire team";
                    //}
                    //$this->SendEmailSendGrid($approvalEmail, $subject, $message, $this->info_email_address, $this->application_name . ' Support');

                    //// notification for the author
                    //if ($designInfo['OwnerUID'] != $this->currentUserId && $authorInfo["Email"] != '')
                    //{
                    //    $designName = $designInfo['DisplayName'];
                    //    if ($designName == NULL || $designName == false || $designName == '')
                    //    {
                    //        $designName = "untitled design";
                    //    }
                    //    else
                    //    {
                    //        $designName = "'" . $designName . "'";
                    //    }
                    //    $link = "makersempire:///?design=" . str_replace("-", "", $DesignUID);
                    //    $subject = "New photo has been added to your design";
                    //    $message = "Hello " . $authorInfo["UserName"] . ",";
                    //    $message = $message . "<br/><br/>" . $userName . " just added a new photo to your design " . $designName . "...";
                    //    $message = $message . "<br/><a href=\"" . $link . "\">" . $this->application_name . "</a>";
                    //    $message = $message . "<br/><br/>Thanks,<br/>Makers Empire team";
                    //    $this->SendEmailSendGrid($authorInfo["Email"], $subject, $message, $this->info_email_address, $this->application_name . ' Support');
                    //}
                }
            }
            else
            {
                # remove photo
                FileHandler::deleteImageFile($pictureUrl);
                $pictureUrl = '';
                # and thumbnail
                if ($thumbnailUrl != '')
                {
                    FileHandler::deleteImageFile($thumbnailUrl);
                }
            }
        }

        $arr["result"] = $pictureUrl == '' ? 0 : 1;

        return json_encode($arr);
    }

    function ApproveDesignPhoto()
    {
        $designPhotoUID = $this->getCleanValueFromArguments('photoID', true);
        $token = $this->getCleanValueFromArguments('token', true);

        // check if the proto still exists
        $sql = "select count(\"DesignPhotoUID\") as final_count from \"DesignPhotos\" where \"DesignPhotoUID\" = '?photo_Id?'";
        $sql = str_replace("?photo_Id?", $designPhotoUID, $sql);
        $count = $this->db->fetchValue($sql);
        if ($count == 0)
        {
            return $this->JsonError("The photo is no longer available.", 'ServerMessage28');
        }

        // check if the token is right and if the designs still needs to be approved
        $sql = "select count(*) from \"DesignPhotos\" where \"ApprovalToken\" = '?token?' and \"DesignPhotoUID\" = '$designPhotoUID'";
        $sql = str_replace("?token?", $token, $sql);
        $count = $this->db->fetchValue($sql);
        if ($count == 0)
        {
            return $this->JsonError("The token is not valid or the photo has already been approved.", 'ServerMessage29');
        }

        $queryResult = $this->db->exesql("update \"DesignPhotos\" set \"IsAccepted\" = 'true' where \"DesignPhotoUID\"='$designPhotoUID'");
        if (pg_affected_rows($queryResult) > 0)
        {
            $this->db->exesql("update \"DesignPhotos\" set \"ApprovalToken\" = '' where \"DesignPhotoUID\" = '$designPhotoUID'");

            $photoInfo = $this->db->fetchArray("select p.\"PhotoUrl\", p.\"DesignUID\", p.\"UserUID\" as \"OwnerUID\", u.\"UserName\" as \"OwnerName\" from \"DesignPhotos\" p left join \"User\" u on u.\"UserUID\" = p.\"UserUID\" where \"DesignPhotoUID\" = '$designPhotoUID'");
            if ($photoInfo)
            {
                $designInfo = $this->db->fetchArray("select \"OwnerUID\", \"DisplayName\", \"PictureUrl\" from \"Design\" where \"DesignUID\" = '" . $photoInfo['DesignUID'] . "'");

                // send a notification to design's owner if the photo was added by other user
                if ($designInfo)
                {
                    $authorInfo = $this->db->fetchArray("select \"Email\", \"UserName\" from \"User\" where \"UserUID\" = '" . $designInfo['OwnerUID'] . "'");

                    if ($designInfo['OwnerUID'] != $photoInfo['OwnerUID'] && $authorInfo && $authorInfo["Email"] != '')
                    {
                        $designName = $designInfo['DisplayName'];
                        if ($designName == NULL || $designName == false || $designName == '')
                        {
                            $designName = "untitled design";
                        }
                        else
                        {
                            $designName = "'" . $designName . "'";
                        }
                        $link = "makersempire:///?design=" . str_replace("-", "", $photoInfo['DesignUID']);

                        $subject = "New photo has been added to your design!";
                        //$message = "Hello " . $authorInfo["UserName"] . ",";
                        //$message = $message . "<br/><br/>" . $photoInfo['OwnerName'] . " just added a new photo to your design " . $designName . "...";
                        //$message = $message . "<br/><a href=\"" . $link . "\">" . $this->application_name . "</a>";
                        //$message = $message . "<br/><br/>Thanks,<br/>Makers Empire team";
                        //$this->SendEmailSendGrid($authorInfo["Email"], $subject, $message, $this->info_email_address, $this->application_name . ' Support');
                        $globalMergeVars = array(
                            array('name' => 'USERNAME', 'content' => $authorInfo["UserName"]),
                            array('name' => 'INITIATOR', 'content' => $photoInfo["OwnerName"]),
                            array('name' => 'DESIGNNAME', 'content' => $designName),
                            array('name' => 'PHOTOID', 'content' => $photoInfo["PhotoUrl"])
                        );
                        $this->SendEmailMandrill("photo-added", $globalMergeVars, $authorInfo["Email"], $subject, $this->info_email_address, $this->application_name, "false");
                    }
                }
            }

            $arr["result"] = 1;
            return json_encode($arr);
        }
        else
        {
            return $this->JsonError("Unknown error has occurred while trying to approve the photo.", 'ServerMessage30');
        }
    }

    function RejectDesignPhoto()
    {
        $designPhotoUID = $this->getCleanValueFromArguments('photoID', true);
        $token = $this->getCleanValueFromArguments('token', true);

        // check if the proto still exists
        $sql = "select count(\"DesignPhotoUID\") as final_count from \"DesignPhotos\" where \"DesignPhotoUID\"='?photo_Id?'";
        $sql = str_replace("?photo_Id?", $designPhotoUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            return $this->JsonError("The photo is no longer available.", 'ServerMessage28');
        }

        // check if the token is right and if the designs wasn't already approved
        $sql = "select count(*) from \"DesignPhotos\" where \"ApprovalToken\" = '?token?' and \"DesignPhotoUID\" = '?photo_Id?'";
        $sql = str_replace("?photo_Id?", $designPhotoUID, $sql);
        $sql = str_replace("?token?", $token, $sql);
        $count = $this->db->fetchValue($sql);
        if ($count == 0)
        {
            return $this->JsonError("The token is not valid or the photo has already been approved.", 'ServerMessage29');
        }

        $designPhotoUrl = $this->db->fetchValue("select \"PhotoUrl\" from \"DesignPhotos\" where \"DesignPhotoUID\" = '$designPhotoUID'");
        $designThumbnailUrl = $this->db->fetchValue("select \"ThumbnailUrl\" from \"DesignPhotos\" where \"DesignPhotoUID\" = '$designPhotoUID'");

        # delete from social db
        $queryResult = $this->db->exesql("delete from \"DesignPhotos\" where \"DesignPhotoUID\"='$designPhotoUID'");
        if (pg_affected_rows($queryResult) > 0)
        {
            $arr["result"] = 1;

            # remove photo
            if ($designPhotoUrl != '')
            {
                FileHandler::deleteImageFile($designPhotoUrl);
            }
            # and thumbnail
            if ($designThumbnailUrl != '')
            {
                FileHandler::deleteImageFile($designThumbnailUrl);
            }

            return json_encode($arr);
        }
        else
        {
            return $this->JsonError("Unknown error has occurred while trying to remove the photo.", 'ServerMessage30');
        }
    }

    function RemoveDesignPhoto()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $arr["DesignUID"] = $DesignUID;

        // don't do anything if the design was removed in the meantime
        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["result"] = 0;
            $arr["msg"] = "Selected design is no longer available";
            $arr["msgKey"] = 'ServerMessage90';
            return json_encode($arr);
        }
        else
        {
            $DesignPhotoUID = $this->getCleanValueFromArguments('DesignPhotoUID', true);
            $arr["DesignPhotoUID"] = $DesignPhotoUID;

            // don't do anything if the photo was removed in the meantime
            $sql = "select count(\"DesignPhotoUID\") as final_count from \"DesignPhotos\" where \"DesignPhotoUID\"='?designPhoto_Id?'";
            $sql = str_replace("?designPhoto_Id?", $DesignPhotoUID, $sql);
            $count = $this->db->fetchValue($sql);
            if($count == 0)
            {
                $arr["result"] = 1;
                $arr["msg"] = "Selected photo is no longer available";
                $arr["msgKey"] = 'ServerMessage93';
                return json_encode($arr);
            }
            else
            {
                $designOwnerUID = $this->db->fetchValue("select \"OwnerUID\" from \"Design\" where \"DesignUID\"='$DesignUID'");
                $photoOwnerUID = $this->db->fetchValue("select \"UserUID\" from \"DesignPhotos\" where \"DesignPhotoUID\"='$DesignPhotoUID'");
                if ($designOwnerUID == $this->currentUserId || $photoOwnerUID == $this->currentUserId)
                {
                    $designPhotoUrl = $this->db->fetchValue("select \"PhotoUrl\" from \"DesignPhotos\" where \"DesignPhotoUID\"='$DesignPhotoUID'");
                    $designThumbnailUrl = $this->db->fetchValue("select \"ThumbnailUrl\" from \"DesignPhotos\" where \"DesignPhotoUID\"='$DesignPhotoUID'");

                    # delete from social db
                    $sql = "delete from \"DesignPhotos\" where \"DesignPhotoUID\"='$DesignPhotoUID'";
                    $queryResult = $this->db->exesql($sql);
                    if (pg_affected_rows($queryResult) > 0)
                    {
                        $arr["result"] = 1;

                        # remove photo
                        if ($designPhotoUrl != '')
                        {
                            FileHandler::deleteImageFile($designPhotoUrl);
                        }
                        # and thumbnail
                        if ($designThumbnailUrl != '')
                        {
                            FileHandler::deleteImageFile($designThumbnailUrl);
                        }
                    }
                    else
                    {
                        $arr["result"] = 2;
                        $arr["msg"] = "Unknown error has occurred while trying to remove the photo";
                        $arr["msgKey"] = 'ServerMessage31';
                    }
                }
                else
                {
                    $arr["result"] = 2;
                    $arr["msg"] = "You can only remove photos that belong to you or are attached to your design";
                    $arr["msgKey"] = 'ServerMessage94';
                }
            }
        }

        return json_encode($arr);
    }

    // this function won't be used - right now the teachers or our team approves photos using ApproveDesignPhoto function
    function AcceptDesignPhoto()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $arr["DesignUID"] = $DesignUID;

        // don't do anything if the design was removed in the meantime or the user doesn't own it
        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?' and \"OwnerUID\"='$this->currentUserId'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["result"] = 0;
            $arr["msg"] = "Selected design is no longer available or doesn't belong to you";
            $arr["msgKey"] = 'ServerMessage95';
            return json_encode($arr);
        }
        else
        {
            $DesignPhotoUID = $this->getCleanValueFromArguments('DesignPhotoUID', true);
            $arr["DesignPhotoUID"] = $DesignPhotoUID;

            // don't do anything if the photo was removed in the meantime
            $sql = "select count(\"DesignPhotoUID\") as final_count from \"DesignPhotos\" where \"DesignPhotoUID\"='?designPhoto_Id?'";
            $sql = str_replace("?designPhoto_Id?", $DesignPhotoUID, $sql);
            $count = $this->db->fetchValue($sql);
            if($count == 0)
            {
                $arr["result"] = 2;
                $arr["msg"] = "Selected photo is no longer available";
                $arr["msgKey"] = 'ServerMessage93';
                return json_encode($arr);
            }
            else
            {
                $sql = "update \"DesignPhotos\" set \"IsAccepted\" = 'true' where \"DesignPhotoUID\"='$DesignPhotoUID'";
                $queryResult = $this->db->exesql($sql);
                if (pg_affected_rows($queryResult) > 0)
                {
                    $arr["result"] = 1;
                }
                else
                {
                    $arr["result"] = 3;
                    $arr["msg"] = "Unknown error has occurred while trying to accept the photo";
                    $arr["msgKey"] = 'ServerMessage96';
                }
            }
        }

        return json_encode($arr);
    }

    function GetMoreDesignPhotos()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $limit = $this->getCleanValueFromArguments('Limit');
        if ($limit == '' || $limit == 0)
            $limit = 6;

        $photosToSkip = $this->getCleanValueFromArguments('PhotosToSkip');
        if ($photosToSkip != '')
        {
            $photosToSkipArray = explode(',', $photosToSkip);
            foreach ($photosToSkipArray as &$singleID)
            {
                $singleID = "'".$singleID."'";
            }
            unset($singleID);
            $photosToSkip = implode(',', $photosToSkipArray);
            $photosToSkip = " and \"DesignPhotoUID\" not in (" . $photosToSkip . ")";
        }

        $photos = $this->GetDesignPhotos($DesignUID, $limit, $photosToSkip);

        $arr['result'] = 1;
        $arr['DesignUID'] = $DesignUID;
        if ($photos && $photos != '')
            $arr['DesignPhotos'] = $photos;

        return json_encode($arr);
    }

    function LikeDesign()
    {
    	$this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        // don't do anything if the design was removed in the meantime
        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            die($this->JsonError("Design was not found in the database", 'ServerMessage26'));
        }

        $arr["DesignUID"] = $DesignUID;
        $arr["result"] = 1;

        if($this->IsDesignLikedByMe($DesignUID) == 0)
        {
            $sql = "insert into \"Like\" (\"DesignUID\", \"UserUID\") values ('?design_Id?', '?my_Id?')";
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
            else
            {
                $this->db->exesql("update \"Design\" set \"Likes\"=\"Likes\" + 1 where \"DesignUID\"='$DesignUID'");
                $authorId = $this->db->fetchValue("select \"OwnerUID\" from \"Design\" where \"DesignUID\" = '$DesignUID'");

                if ($authorId != $this->currentUserId)
                {
                    // send notification
                    $userName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\" = '$this->currentUserId'");
                    $authorInfo = $this->db->fetchArray("select \"Email\", \"UserName\" from \"User\" where \"UserUID\" = '$authorId'");
                    $designName = $this->db->fetchValue("select \"DisplayName\" from \"Design\" where \"DesignUID\" = '$DesignUID'");
                    $numLikes = $this->db->fetchValue("select \"Likes\" from \"Design\" where \"DesignUID\"= '$DesignUID'");
                    if ($designName == NULL || $designName == false || $designName == '')
                    {
                        $designName = "untitled design";
                    }
                    //else
                    //{
                    //    $designName = "'" . $designName . "'";
                    //}
                    $link = "makersempire:///?design=" . str_replace("-", "", $DesignUID);

                    $subject = "Your design has been liked!";
                    //$message = "Hello " . $authorInfo["UserName"] . ",";
                    //$message = $message . "<br/><br/>" . $userName . " just liked your " . $designName . "... see other recently liked designs...";
                    //$message = $message . "<br/><a href=\"" . $link . "\">" . $this->application_name . "</a>";
                    //$message = $message . "<br/><br/>Thanks,<br/>Makers Empire team";
                    //$this->SendEmailSendGrid($authorInfo["Email"], $subject, $message, $this->info_email_address, $this->application_name . ' Support');
                    $globalMergeVars = array(
	 	        array('name' => 'USERNAME', 'content' => $authorInfo["UserName"]),
                        array('name' => 'INITIATOR', 'content' => $userName),
    	                array('name' => 'DESIGNNAME', 'content' => $designName),
                        array('name' => 'DESIGNID', 'content' => $DesignUID),
    		        array('name' => 'NUMLIKES', 'content' => $numLikes)
	    	    );
                    $this->SendEmailMandrill("design-liked-notification", $globalMergeVars, $authorInfo["Email"], $subject, $this->info_email_address, $this->application_name, "false");

                    // liked designs are synced to makerbot account (if linked)
                    $this->SyncToMakerBot($this->currentUserId);

                   // add notification to user who's design was liked
                   $designNameForNotification = $designName == "untitled design" ? "untitled" : $designName;
                   $message = "$userName has liked your $designNameForNotification design!";
                   $sql = "insert into notifications (type_of, text, image_url, language, user_id, design_id) values ('liked', '$message', 'liked', 'en-GB', '$authorId', '$DesignUID')";
                   $this->db->exesql($sql);
                }
            }
        }

        return json_encode($arr);
    }

    function UnlikeDesign()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        $arr["DesignUID"] = $DesignUID;
        $arr["result"] = 1;

        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count > 0)
        {
            $sql = "delete from \"Like\" where \"DesignUID\"='?design_Id?' and \"UserUID\"='?my_Id?'";
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
            else
            {
                $this->db->exesql("update \"Design\" set \"Likes\"=\"Likes\" - 1 where \"DesignUID\"='$DesignUID'");
            }
        }

        return json_encode($arr);
    }
    
    function IncrementViewCount()
    {
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        $sql = "update \"Design\" set \"ViewCount\"=\"ViewCount\" + 1 where \"DesignUID\"='?design_Id?' returning \"ViewCount\"";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $ret = $this->db->fetchValue($sql);

        $result["DesignUID"] = $DesignUID;
        if ($ret)
        {
            $result["ViewCount"] = $ret;
            $result["result"] = 1;
        }
        else
        {
            $result["result"] = 0;
        }

        return json_encode($result);
    }

    function ShareDesign()
    {
        $this->checkUser(true);

        $isShared = $this->getCleanValueFromArguments('IsShared');

        $sql = "update \"Design\" set \"IsShared\"='?is_shared?' where \"DesignUID\"='?design_Id?' and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?design_Id?", $this->getCleanValueFromArguments('LevelUID'), $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?is_shared?", $isShared, $sql);
        $this->db->exesql($sql);

        $result["LevelUID"] = $this->getCleanValueFromArguments('LevelUID');
        $result["IsShared"] = $this->getCleanValueFromArguments('IsShared');
        $result["result"] = 1;
        return json_encode($result);
    }

    function AddComment()
    {
        $this->checkUser(true);

        $DesignUID = $this->getCleanValueFromArguments('DesignUID');
        $minID = $this->getCleanValueFromArguments('LatestID');
        $text = $this->getCleanValueFromArguments('Text');

        // scan for bad words
        $badWordRegex = $this->ContainsBadWord($text, "user id - $this->currentUserId tried to comment on design with ID - $DesignUID", "insert into \"Comment\" (\"UserUID\", \"DesignUID\", \"Date\", \"Text\") values (''$this->currentUserId'', ''$DesignUID'', localtimestamp, ''$text'')");
        if ($badWordRegex)
        {
            $result["result"] = 1;
            $result["msg"] = "text ($text) contains a restricted word matching the regex $badWordRegex";
            return json_encode($result);
        }

        // check if design exists
        $sql = "select count(\"DesignUID\") as final_count from \"Design\" where \"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $count = $this->db->fetchValue($sql);
        if ($count == 0)
        {
            $result["result"] = 0;
            $result["msg"] = "Design does not exist.";
            $result["msgKey"] = 'ServerMessage97';
            $result["DesignUID"] = $DesignUID;

            return json_encode($result);
        }

        $sql = "insert into \"Comment\" (\"UserUID\", \"DesignUID\", \"Date\", \"Text\") values ('?my_Id?', '?design_Id?', '?date?', '?text?')";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?date?", $this->getCleanValueFromArguments('Date'), $sql);
        $sql = str_replace("?text?", $text, $sql);

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) > 0)
        {
            $sql = "update \"Design\" set \"Comments\"=\"Comments\" + 1 where \"DesignUID\"='?design_Id?'";
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $this->db->exesql($sql);

            # get the latest comments
            $sql = "select c.\"CommentUID\", c.\"UserUID\", c.\"Date\", c.\"Text\", c.\"Likes\", c.\"Dislikes\", u.\"UserName\", u.\"PictureUrl\" from \"Comment\" c left join \"User\" u on u.\"UserUID\" = c.\"UserUID\" where c.\"DesignUID\"='?design_Id?' and c.\"CommentUID\" > $minID order by c.\"CommentUID\" desc";
            $sql = str_replace("?design_Id?", $DesignUID, $sql);
            $comments = $this->db->sqlToArray($sql);

            if ($comments)
            {
                for ($i=0; $i < count($comments); $i++)
                {
                    $comments[$i]['MyRate'] = $this->MyCommentsRate($comments[$i]['CommentUID']);
                }
                $result["comments"] = $comments;
            }

            $result["result"] = 1;
            $authorId = $this->db->fetchValue("select \"OwnerUID\" from \"Design\" where \"DesignUID\" = '$DesignUID'");

            if($authorId != $this->currentUserId)
            {
                // send notification
                $userName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\" = '$this->currentUserId'");
                $authorInfo = $this->db->fetchArray("select \"Email\", \"UserName\" from \"User\" where \"UserUID\" = '$authorId'");
                $designName = $this->db->fetchValue("select \"DisplayName\" from \"Design\" where \"DesignUID\" = '$DesignUID'");
                if ($designName == NULL || $designName == false || $designName == '')
                {
                    $designName = "untitled design";
                }
                //else
                //{
                //    $designName = "'" . $designName . "'";
                //}
                $link = "makersempire:///?design=" . str_replace("-", "", $DesignUID);

                //$subject = "Other user has posted a comment to your design!";
                $subject = $userName . " has commented on your " . $designName . " design!";
                //$message = "Hello " . $authorInfo["UserName"] . ",";
                //$message = $message . "<br/><br/>" . $userName . " just posted a comment: \"" . $text . "\" to your " . $designName . "... see other comments...";
                //$message = $message . "<br/><a href=\"" . $link . "\">" . $this->application_name . "</a>";
                //$message = $message . "<br/><br/>Thanks,<br/>Makers Empire team";
                //$this->SendEmailSendGrid($authorInfo["Email"], $subject, $message, $this->info_email_address, $this->application_name . ' Support');
                $globalMergeVars = array(
                    array('name' => 'USERNAME', 'content' => $authorInfo["UserName"]),
                    array('name' => 'INITIATOR', 'content' => $userName),
                    array('name' => 'COMMENT', 'content' => $text),
                    array('name' => 'DESIGNNAME', 'content' => $designName),
                    array('name' => 'DESIGNID', 'content' => $DesignUID)
                );
                $this->SendEmailMandrill("comment-added", $globalMergeVars, $authorInfo["Email"], $subject, $this->info_email_address, $this->application_name, "false");

                // add notification to user who's design was liked
                $designNameForNotification = $designName == "untitled design" ? "untitled" : $designName;
                $message = "$userName has commented on your $designNameForNotification design!";
                $sql = "insert into notifications (type_of, text, image_url, language, user_id, design_id) values ('comment', '$message', 'comment', 'en-GB', '$authorId', '$DesignUID')";
                $this->db->exesql($sql);
            }
        }
        else
        {
            $result["result"] = 0;
        }
        $result["DesignUID"] = $DesignUID;

        return json_encode($result);
    }

    function UpdateComment()
    {
        $comment_id = $this->getCleanValueFromArguments("comment_id");
        $updated_text = $this->getCleanValueFromArguments("updated_text");

        // scan for bad words
        $badWordRegex = $this->ContainsBadWord($updated_text, "while updating comment id - $comment_id", "update \"Comment\" set \"Text\" = ''$updated_text'' where \"CommentUID\" = ''$comment_id''");
        if ($badWordRegex)
        {
            $result["result"] = 1;
            $result["msg"] = "text ($updated_text) contains a restricted word matching the regex $badWordRegex";
            return json_encode($result);
        }

        $sql = "update \"Comment\" set \"Text\" = '$updated_text' where \"CommentUID\" = '$comment_id'";
        $queryResult = $this->db->exesql($sql);

        $result["comment_id"] = $comment_id;
        if (pg_affected_rows($queryResult) > 0)
        {
            $sql = "select \"DesignUID\" from \"Comment\" where \"CommentUID\" = '$comment_id'";
            $design_id = $this->db->fetchValue($sql);

            $result["result"] = 1;
            $result["updated_text"] = $updated_text;
            $result["design_id"] = $design_id;
        }
        else
            $result["result"] = 0;

        return json_encode($result);
    }

    function DeleteComment()
    {
        $comment_id = $this->getCleanValueFromArguments("comment_id");
        $design_uid = $this->getCleanValueFromArguments("design_uid");

        // delete the comment itself here
        $sql = "delete from \"Comment\" where \"CommentUID\" = '$comment_id'";

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) > 0)
        {
            // remove a like from the count on the design itself
            if ($design_uid)
            {
                $sql = "update \"Design\" set \"Comments\"=\"Comments\" - 1 where \"DesignUID\" = '$design_uid'";
                $this->db->exesql($sql);
            }

            $result["result"] = 1;
            $result["design_uid"] = $design_uid;
            $result["comment_id"] = $comment_id;
            // delete all rating for this comment
            $sql = "delete from \"CommentRating\" where \"CommentUID\" = '$comment_id'";
            $this->db->exesql($sql);
        }
        else
        {
            $result["result"] = 0;
            $result["comment_id"] = $comment_id;
        }

        return json_encode($result);
    }

    function GetComments()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $CommentID = $this->getCleanValueFromArguments('CommentUID', true); // when getting newer comments
        $limit = $this->getCleanValueFromArguments('Limit');
        $existing_ids = $this->getCleanValueFromArguments("existing_ids");

        $sql = "select c.\"CommentUID\", c.\"UserUID\", c.\"Date\", c.\"Text\", c.\"Likes\", c.\"Dislikes\", u.\"UserName\", u.\"PictureUrl\" from \"Comment\" c left join \"User\" u on u.\"UserUID\" = c.\"UserUID\" where c.\"DesignUID\"='?design_Id?'";
        $sql = str_replace("?design_Id?", $DesignUID, $sql);

        if ($limit == 0)
        {
            # refreshing
            $sql = $sql . " and c.\"CommentUID\" > $CommentID order by c.\"CommentUID\" desc";
        }
        else
        {
            if ($CommentID == 0)
            {
                # getting list for the first time
                $sql = $sql . " order by c.\"Likes\" desc limit $limit";
            }
            else
            {
                # requesting older comments
                if ($existing_ids)
                    $sql = $sql . "and c.\"CommentUID\" not in ($existing_ids) order by c.\"Likes\" desc limit $limit";
                else
                    $sql = $sql . "and c.\"CommentUID\" < $CommentID order by c.\"CommentUID\" desc limit $limit";
            }
        }

        $comments = $this->db->sqlToArray($sql);

        if ($comments)
        {
            if ($isUserLoggedIn)
            {
                for ($i=0; $i < count($comments); $i++)
                {
                    $comments[$i]['MyRate'] = $this->MyCommentsRate($comments[$i]['CommentUID']);
                }
            }
            else
            {
                for ($i=0; $i < count($comments); $i++)
                {
                    $comments[$i]['MyRate'] = "0";
                }
            }

            $result["result"] = 1;
            $result["comments"] = $comments;
        }
        else
        {
            $result["result"] = 0;
        }
        $result["DesignUID"] = $DesignUID;

        return json_encode($result);
    }

    function RateComment()
    {
        $this->checkUser(true);

        $CommentUID = $this->getCleanValueFromArguments('CommentUID', true);
        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);

        $arr["DesignUID"] = $DesignUID;
        $arr["CommentUID"] = $CommentUID;

        // don't do anything if the comment doesn't exist
        $sql = "select count(\"CommentUID\") as final_count from \"Comment\" where \"CommentUID\"='?comment_Id?'";
        $sql = str_replace("?comment_Id?", $CommentUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["result"] = 0;
            $arr["msg"] = "Comment was not found in the database.";
            $arr["msgKey"] = 'ServerMessage98';

            return json_encode($arr);
        }

        $myOldRate = $this->MyCommentsRate($CommentUID);
        $myNewRate = $this->getCleanValueFromArguments('MyRate', true);
        if ($myNewRate == $myOldRate)
        {
            $arr["result"] = 1;
        }
        else
        {
            if ($myNewRate == 0)
            {
                $sql = "delete from \"CommentRating\" where \"CommentUID\"='?comment_Id?' and \"UserUID\"='?my_Id?'";
                $sql = str_replace("?comment_Id?", $CommentUID, $sql);
                $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

                $queryResult = $this->db->exesql($sql);
                $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
            }
            else
            {
                if ($myOldRate == 0)
                {
                    $sql = "insert into \"CommentRating\" (\"CommentUID\", \"UserUID\", \"Rate\") values ('?comment_Id?', '?my_Id?', '?rate?')";
                }
                else
                {
                    $sql = "update \"CommentRating\" set \"Rate\"='?rate?' where \"CommentUID\"='?comment_Id?' and \"UserUID\"='?my_Id?'";
                }
                $sql = str_replace("?comment_Id?", $CommentUID, $sql);
                $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
                $sql = str_replace("?rate?", $myNewRate, $sql);

                $queryResult = $this->db->exesql($sql);
                $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
            }

            if ($arr["result"] == 1)
            {
                if ($myOldRate > 0)
                {
                    if ($myNewRate < 0)
                    {
                        $this->db->exesql("update \"Comment\" set \"Likes\"=\"Likes\" - 1, \"Dislikes\"=\"Dislikes\" + 1 where \"CommentUID\"='$CommentUID'");
                    }
                    else
                    {
                        $this->db->exesql("update \"Comment\" set \"Likes\"=\"Likes\" - 1 where \"CommentUID\"='$CommentUID'");
                    }
                }
                else if ($myOldRate == 0)
                {
                    if ($myNewRate > 0)
                    {
                        $this->db->exesql("update \"Comment\" set \"Likes\"=\"Likes\" + 1 where \"CommentUID\"=$CommentUID");
                    }
                    else
                    {
                        $this->db->exesql("update \"Comment\" set \"Dislikes\"=\"Dislikes\" + 1 where \"CommentUID\"=$CommentUID");
                    }
                }
                else
                {
                    if ($myNewRate > 0)
                    {
                        $this->db->exesql("update \"Comment\" set \"Likes\"=\"Likes\" + 1, \"Dislikes\"=\"Dislikes\" - 1 where \"CommentUID\"=$CommentUID");
                    }
                    else
                    {
                        $this->db->exesql("update \"Comment\" set \"Dislikes\"=\"Dislikes\" - 1 where \"CommentUID\"=$CommentUID");
                    }
                }
            }
        }

        $arr["MyRate"] = $myNewRate;

        return json_encode($arr);
    }

    function AddMesh()
    {
        $this->checkUser(true);

        $meshName = $this->getCleanValueFromArguments('DisplayName');

        if ($this->ContainsBadWord($meshName, "user id - $this->currentUserId was trying to add a new mesh", ""))
            $meshName = "Shape";

        // if we are ensuring unique name, we overwrite whatever mesh is called the same thing
        if ($this->getCleanValueFromArguments('EnsureUniqueName') == 1)
        {
            $MeshUID = $this->db->fetchValue("select \"MeshUID\" from \"Mesh\" where \"DisplayName\" = '$meshName'");
            if ($MeshUID != "")
            {
                $this->arguments['MeshUID'] = $MeshUID;
                return $this->EditMesh();
            }
        }
 

        $MeshUID = $this->getCleanValueFromArguments('MeshUID', true);

        $sql = "select count(\"MeshUID\") as final_count from \"Mesh\" where \"MeshUID\"='?mesh_Id?'";
        $sql = str_replace("?mesh_Id?", $MeshUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count > 0)
        {
            return $this->EditMesh();
        }

        $type = 0;
        if (isset($this->arguments["MeshType"]))
            $type = (int)$this->getCleanValueFromArguments('MeshType');

        $sql = "insert into \"Mesh\" (\"MeshUID\", \"OwnerUID\", \"Data\", \"ModificationDate\", \"DisplayName\", \"IsPublic\", type, picture_url, large_picture_url) values ('?mesh_Id?', '?user_Id?', decode('?data?', 'base64'), '?modificationDate?', '?name?', '?is_public?', '?type?', '?picture_url?', '?large_picture_url?')";
        $sql = str_replace("?user_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?mesh_Id?", $MeshUID, $sql);
        $sql = str_replace("?name?", $this->getCleanValueFromArguments('DisplayName'), $sql);
        $sql = str_replace("?is_public?", $this->getCleanValueFromArguments('IsPublic'), $sql);
        $sql = str_replace("?type?", $type, $sql);
        $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);
        $sql = str_replace("?data?", $this->getCleanValueFromArguments('Data', true), $sql);

        // save picture file and get url if data exists
        if (count($_FILES) > 0)
        {
            $fileHandler = new FileHandler();

            if (isset($_FILES['ImageData']) && is_uploaded_file($_FILES['ImageData']['tmp_name']) && $_FILES['ImageData']['error'] == 0)
            {
                $fileRelativePath = 'img/mesh/thumbnail/' . $MeshUID . '.jpg';
                $pictureUrl = $fileHandler->moveFile($_FILES['ImageData']['tmp_name'], $fileRelativePath);
            }
            else
            {
                error_log("Thumbnail for $MeshUID not saved - isset " . isset($_FILES['ImageData']) . " is_uploaded_file " . is_uploaded_file($_FILES['ImageData']['tmp_name']) . " error " . $_FILES['ImageData']['error']);
                $pictureUrl = '';
            }

            if (isset($_FILES['LargeImageData']) && is_uploaded_file($_FILES['LargeImageData']['tmp_name']) && $_FILES['LargeImageData']['error'] == 0)
            {
                $fileRelativePath = 'img/mesh/' . $MeshUID . '_lrg.jpg';
                $largePictureUrl = $fileHandler->moveFile($_FILES['LargeImageData']['tmp_name'], $fileRelativePath);

                if ($pictureUrl == '' && $largePictureUrl != '')
                {
                    $fileRelativePath = 'img/mesh/thumbnail/' . $MeshUID . '.jpg';
                    $pictureUrl = $fileHandler->createResizedTexture($largePictureUrl, $fileRelativePath, 64);
                }
            }
            else
            {
                error_log("Large Url for $MeshUID not saved - isset " . isset($_FILES['LargeImageData']) . " is_uploaded_file " . is_uploaded_file($_FILES['LargeImageData']['tmp_name']) . " error " . $_FILES['LargeImageData']['error']);
                $largePictureUrl = '';
            }
        }
        else
        {
            if ($type > 0)
                error_log("no image files set for $MeshUID");

            $pictureUrl = '';
            $largePictureUrl = '';
        }

        if ($type > 0 && $pictureUrl == '')
        {
            $result["msg"] = "Failed to save shape image";
            $result["msgKey"] = 'ServerMessage99';
        }

        $sql = str_replace("?picture_url?", $pictureUrl, $sql);
        $sql = str_replace("?large_picture_url?", $largePictureUrl, $sql);

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) == 0)
        {
            // need to find out the reason and handle the error somehow (is there a chance the MeshUID already existis in the table?)
            die($this->JsonError("Unknown error has occurred while trying to add new shape", 'ServerMessage32'));
        }
        else
        {
            # add tags to mesh
            $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
            foreach ($tagArray as $singleTag)
            {
                if (trim($singleTag) != '')
                {
                    if ($this->ContainsBadWord($singleTag, "user id - $this->currentUserId tried adding mesh tag to mesh id - $MeshUID", "insert into \"MeshTag\" (\"MeshUID\", \"TagText\") values (''$MeshUID'', ''$singleTag'')"))
                        continue;

                    $this->AddSingleTagToMesh($singleTag, $MeshUID);
                }
            }

            if ($this->getCleanValueFromArguments('IsInDrawer') == 1)
            {
                $sql = "insert into \"MeshDrawer\" (\"MeshUID\", \"UserUID\") values ('?mesh_Id?', '?my_Id?')";
                $sql = str_replace("?mesh_Id?", $MeshUID, $sql);
                $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

                $this->db->exesql($sql);
            }
            if ($this->getCleanValueFromArguments('IsInToyDesignerDrawer') == 1)
            {
                $sql = "insert into \"MeshDrawerToyDesigner\" (\"MeshUID\", \"UserUID\") values ('?mesh_Id?', '?my_Id?')";
                $sql = str_replace("?mesh_Id?", $MeshUID, $sql);
                $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

                $this->db->exesql($sql);
            }
        }

        $result["MeshUID"] = $MeshUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function EditMesh()
    {
        $this->checkUser(true);

        $MeshUID = $this->getCleanValueFromArguments('MeshUID', true);

        if (isset($this->arguments["Data"]))
        {
            $sql = "update \"Mesh\" set (\"ModificationDate\", \"DisplayName\", \"Data\") = ('?modificationDate?', '?name?', decode('?data?', 'base64')) where \"MeshUID\" = '?mesh_Id?' and \"OwnerUID\" = '?my_Id?' ";
            $sql = str_replace("?data?", $this->getCleanValueFromArguments('Data', true), $sql);
        }
        else
            $sql = "update \"Mesh\" set (\"ModificationDate\", \"DisplayName\") = ('?modificationDate?', '?name?') where \"MeshUID\" = '?mesh_Id?' and \"OwnerUID\" = '?my_Id?' ";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?mesh_Id?", $MeshUID, $sql);

        $meshName = $this->getCleanValueFromArguments("DisplayName");
        if ($this->ContainsBadWord($meshName, "user id - $this->currentUserId tried to name a shape when creating it", ""))
            $meshName = "Shape";
        $sql = str_replace("?name?", $meshName, $sql);
        $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) == 0)
        {
            // need to find out the reason and handle the error
            die($this->JsonError("Unknown error has occurred while trying to edit a shape", 'ServerMessage33'));
        }
        else
        {
            # remove old tags from mesh
            $this->db->exesql("delete from \"MeshTag\" where \"MeshUID\"='$MeshUID'");

            # add new tags to mesh
            $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
            foreach ($tagArray as $singleTag)
            {
                if (trim($singleTag) != '')
                {
                    $this->AddSingleTagToMesh($singleTag, $MeshUID);
                }
            }
        }

        $result["MeshUID"] = $MeshUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function DeleteMeshByName()
    {
        $this->checkUser(true);

        $displayName = $this->getCleanValueFromArguments('DisplayName', true);

        $meshes = $this->db->sqlToArray("select \"MeshUID\", picture_url, large_picture_url from \"Mesh\" where \"DisplayName\" = '$displayName' and \"OwnerUID\" = '$this->currentUserId'");

        if ($meshes)
        {
            if (count($meshes) > 1)
                die("More than one matching mesh for $displayName");

            if (count($meshes) < 1)
                die("No matching mesh for $displayName");

            # remove old tags from mesh
            $this->db->exesql("delete from \"MeshTag\" where \"MeshUID\"='" . $meshes[0]['MeshUID'] . "'");

            # remove images
            if ($meshes[0]['picture_url'] != '')
                FileHandler::deleteImageFile($meshes[0]['picture_url']);

            if ($meshes[0]['large_picture_url'] != '')
                FileHandler::deleteImageFile($meshes[0]['large_picture_url']);

            $queryResult = $this->db->exesql("delete from \"Mesh\" where \"DisplayName\" = '$displayName' and \"OwnerUID\" = '$this->currentUserId'");

            $result["MeshUID"] = $meshes[0]['MeshUID'];
            $result["result"] = 1;

            return json_encode($result);
        }
        else
        {
            die("Query failed for deleting mesh $displayName");
        }
    }

    function AddMeshTags()
    {
        $this->checkUser(true);

        $MeshUID = $this->getCleanValueFromArguments('MeshUID', true);

        # add new tags to mesh
        $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
        foreach ($tagArray as $singleTag)
        {
            if (trim($singleTag) != '')
            {
                $this->AddSingleTagToMesh($singleTag, $MeshUID, $this->currentUserId);
            }
        }

        $result["MeshUID"] = $MeshUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function AddOrRemoveMeshTags()
    {
        $this->checkUser(true);

        $adding = $this->getCleanValueFromArguments("adding");
        $MeshUID = $this->getCleanValueFromArguments("MeshUID", true);

        // add new tags to mesh
        $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
        foreach ($tagArray as $singleTag)
        {
            if (trim($singleTag) != '')
            {
                if ($adding == "True")
                {
                    $this->AddSingleTagToMesh($singleTag, $MeshUID, $this->currentUserId);
                }
                else
                {
                    $sql = "delete from \"MeshTag\" where \"MeshUID\" = '$MeshUID' and \"TagText\" = '$singleTag'";
                    $this->db->exesql($sql);
                }
            }
        }

        $result["MeshUID"] = $MeshUID;
        $result["result"] = 1;

        return json_encode($result);
    }


    function GetOwnedMeshes()
    {
        $this->checkUser(true);

        $sql = "select \"MeshUID\", \"DisplayName\", \"UseCount\", \"IsPublic\", \"ModificationDate\", picture_url, large_picture_url from \"Mesh\" where \"OwnerUID\"='?user_Id?'";
        $sql = str_replace("?user_Id?", $this->currentUserId, $sql);
        $meshes = $this->db->sqlToArray($sql);

        if ($meshes)
        {
            for ($i=0; $i < count($meshes); $i++)
            {
                if ($this->getCleanValueFromArguments("tData"))
                    $meshes[$i]['MeshTags'] = $this->GetMeshTags($meshes[$i]['MeshUID'], "true");
                else
                    $meshes[$i]['MeshTags'] = $this->GetMeshTags($meshes[$i]['MeshUID'], "false");
            }
            $arr["meshes"] = $meshes;
            $arr["result"] = 1;
        }
        else
        {
            $arr["result"] = 0;
        }

        return json_encode($arr);
    }

    function GetMissingMeshes()
    {
        //$this->checkUser(true);
        $meshIDs = $this->getCleanValueFromArguments('MeshIDs', true);
        $meshArray = explode(',', $meshIDs);
        $meshesFound = array();
        $meshesMissing = array();
        foreach ($meshArray as &$singleID)
        {
            $sql = "select count(\"MeshUID\") as final_count from \"Mesh\" where \"MeshUID\"='$singleID'";
            $count = $this->db->fetchValue($sql);
            if($count == 0)
            {
                $meshesMissing[] = $singleID;
            }
            else
            {
                $meshesFound[] = "'".$singleID."'";
            }
        }
        unset($singleID);

        $resultArray["DesignUID"] = $this->getCleanValueFromArguments('DesignUID', true);
        $meshesSet = true;

        if (count($meshesFound) > 0)
        {
            $meshIDs = implode(',', $meshesFound);

            $sql = "select m.\"MeshUID\", m.\"OwnerUID\", m.\"DisplayName\", m.\"UseCount\", m.\"IsPublic\", m.\"ModificationDate\", m.type, m.picture_url, m.large_picture_url, u.\"UserName\" as \"OwnerName\", u.username_approved, encode(m.\"Data\", 'base64') from \"Mesh\" m left join \"User\" u on u.\"UserUID\" = m.\"OwnerUID\" where m.\"MeshUID\" in ($meshIDs)";;
            $meshes = $this->db->sqlToArray($sql);

            if ($meshes)
            {
                for ($i=0; $i < count($meshes); $i++)
                {
                    if ($this->getCleanValueFromArguments("tData"))
                        $meshes[$i]['MeshTags'] = $this->GetMeshTags($meshes[$i]['MeshUID'], "true");
                    else
                        $meshes[$i]['MeshTags'] = $this->GetMeshTags($meshes[$i]['MeshUID'], "false");

                    // if this username has not been approved, let's replace with ***
                    if ($meshes[$i]["username_approved"] == 'f')
                        $meshes[$i]["OwnerName"] = "*******";
                }
                $resultArray["meshes"] = $meshes;
            }
            else
            {
                $meshesSet = false;
            }
        }
        if (count($meshesMissing) > 0)
        {
            $meshIDs = implode(',', $meshesMissing);

            $subject = "Missing meshes from generator " . $_SERVER['REMOTE_ADDR'] . " on " . gethostbyaddr($_SERVER["SERVER_ADDR"]);
            $message = "Design ID: " . $resultArray["DesignUID"] . "<br/>Mesh IDs: " . $meshIDs;
            if (isset($this->arguments["username"]))
                $message = $message . "<br/>Username: " . $this->arguments["username"];
            else
                $message = $message . "<br/>Username not set";
            $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');

            $resultArray["missingMeshes"] = $meshIDs;
        }

        if ($meshesSet)
        {
            $resultArray["result"] = 1;
        }
        else
        {
            $resultArray["result"] = 0;
        }

        return json_encode($resultArray);
    }

    function GetMeshData()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $MeshUID = $this->getCleanValueFromArguments('MeshUID', true);
        $arr["MeshUID"] = $MeshUID;

        // don't do anything if the mesh doesn't exist
        $sql = "select count(\"MeshUID\") as final_count from \"Mesh\" where \"MeshUID\"='?mesh_Id?'";
        $sql = str_replace("?mesh_Id?", $MeshUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["msg"] = "Shape was not found in the database";
            $arr["msgKey"] = 'ServerMessage100';
            $arr["result"] = 0;

            return json_encode($arr);
        }
        else
        {
            $result = $this->db->fetchArray("select \"ModificationDate\", encode(\"Data\", 'base64') from \"Mesh\" where \"MeshUID\"='$MeshUID'");

            if (!$result)
            {
                $arr["result"] = 0;
                $arr["msg"] = "A problem occurred while getting shape data";
                $arr["msgKey"] = 'ServerMessage108';
            }
            else
            {
                $arr["result"] = 1;
                $arr["encode"] = $result["encode"];
                $arr["ModificationDate"] = $result["ModificationDate"];
            }
        }

        return json_encode($arr);
    }

    function GetMatchingMeshes()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $type = 0;
        if (isset($this->arguments["Type"]))
            $type = (int)$this->getCleanValueFromArguments('Type');
        $limit = $this->getCleanValueFromArguments('Limit');
        $offset = $this->getCleanValueFromArguments('Offset');
        $keywords = $this->getCleanValueFromArguments('Keywords');
        $getOwnedMeshes = $this->getCleanValueFromArguments('Owned');
        $skipItemsInDrawer = $this->getCleanValueFromArguments('SkipInDrawer');
        $isToyDesigner = $this->getCleanValueFromArguments('IsToyDesigner') == 1;

        $tagsArray = array_filter(explode(' ', $keywords));
        $meshIdsString = "";
        if(count($tagsArray) > 0)
        {
            $idArray = $this->GetItemIdsByTags($tagsArray, "Mesh");
            $meshIdsString = implode(',', $idArray);
        }

        // 2D mesh requests return also mesh data, 3D ones don't
        if ($type == 0)
            $sql = "select m.\"MeshUID\", m.\"OwnerUID\", m.\"DisplayName\", m.\"UseCount\", m.\"IsPublic\", m.\"ModificationDate\", m.type, m.picture_url, m.large_picture_url, u.\"UserName\" as \"OwnerName\", u.username_approved, encode(m.\"Data\", 'base64') from \"Mesh\" m left join \"User\" u on u.\"UserUID\" = m.\"OwnerUID\"";
        else
            $sql = "select m.\"MeshUID\", m.\"OwnerUID\", m.\"DisplayName\", m.\"UseCount\", m.\"IsPublic\", m.\"ModificationDate\", m.type, m.picture_url, m.large_picture_url, u.\"UserName\" as \"OwnerName\", u.username_approved from \"Mesh\" m left join \"User\" u on u.\"UserUID\" = m.\"OwnerUID\"";

        if ($getOwnedMeshes == 1)
        {
            $sql = $sql . " where m.\"OwnerUID\" = '$this->currentUserId' and m.type = ?mesh_type? ";
        }
        else
        {
            $sql = $sql . " where (m.\"IsPublic\" = 't' or m.\"OwnerUID\" = '$this->currentUserId') and m.type = ?mesh_type? ";
        }
        if ($isUserLoggedIn && $skipItemsInDrawer == 1)
        {
            if ($isToyDesigner)
                $results = $this->db->exesql("select \"MeshUID\" from \"MeshDrawerToyDesigner\" where \"UserUID\"='$this->currentUserId'");
            else
                $results = $this->db->exesql("select \"MeshUID\" from \"MeshDrawer\" where \"UserUID\"='$this->currentUserId' and \"WasRemoved\" = false");
            $itemsInDrawerIdArray = array();
            while($line = pg_fetch_array($results))
            {
                $itemsInDrawerIdArray[] = "'".$line["MeshUID"]."'";
            }

            $itemsInDrawerIdString = implode(',', $itemsInDrawerIdArray);
            if ($itemsInDrawerIdString != "")
            {
                $sql = $sql . " and m.\"MeshUID\" not in ($itemsInDrawerIdString)";
            }
	}
	if ($meshIdsString != "")
        {
            $sql = $sql . " and m.\"MeshUID\" in ($meshIdsString) union " . $sql;
        }
        $sql = $sql . " and m.\"DisplayName\" ILIKE '%$keywords%' order by \"UseCount\" desc, \"MeshUID\" desc limit $limit offset $offset";
        $sql = str_replace("?mesh_type?", $type, $sql);

        $meshes = $this->db->sqlToArray($sql);

        if ($meshes)
        {
            for ($i=0; $i < count($meshes); $i++)
            {
                if ($this->getCleanValueFromArguments("tData"))
                    $meshes[$i]['MeshTags'] = $this->GetMeshTags($meshes[$i]['MeshUID'], "true");
                else
                    $meshes[$i]['MeshTags'] = $this->GetMeshTags($meshes[$i]['MeshUID'], "false");

                // if this username has not been approved, let's replace with ***
                if ($meshes[$i]["username_approved"] == 'f')
                    $meshes[$i]["OwnerName"] = "*******";
            }
            $resultArray["meshes"] = $meshes;
            $resultArray["result"] = 1;
        }
        else
        {
            $resultArray["result"] = 0;
        }

        return json_encode($resultArray);
    }

    function AddMeshToDrawer()
    {
        $this->checkUser(true);

        $MeshUID = $this->getCleanValueFromArguments('MeshUID', true);
        $arr["MeshUID"] = $MeshUID;
        $isToyDesigner = $this->getCleanValueFromArguments('IsToyDesigner') == 1;

        // don't do anything if the mesh doesn't exist
        $sql = "select count(\"MeshUID\") as final_count from \"Mesh\" where \"MeshUID\"='?mesh_Id?'";
        $sql = str_replace("?mesh_Id?", $MeshUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["msg"] = "Shape was not found in the database";
            $arr["msgKey"] = 'ServerMessage100';
            $arr["result"] = 0;

            return json_encode($arr);
        }

        $arr["result"] = 1;

        $sql = "";
        if($isToyDesigner)
        {
            if ($this->IsMeshInToyDesignerDrawer($MeshUID) == 0)
            {
                $sql = "insert into \"MeshDrawerToyDesigner\" (\"MeshUID\", \"UserUID\") values ('?mesh_Id?', '?my_Id?')";
            }
        }
        else
        {
            if ($this->IsMeshInDrawer($MeshUID) == 0)
            {
                $sql = "insert into \"MeshDrawer\" (\"MeshUID\", \"UserUID\") values ('?mesh_Id?', '?my_Id?')";
            }
            else
            {
                $sql = "update \"MeshDrawer\" set \"WasRemoved\" = false where \"MeshUID\" = '?mesh_Id?' and \"UserUID\" = '?my_Id?'";
            }
        }
        if ($sql != "")
        {
            $sql = str_replace("?mesh_Id?", $MeshUID, $sql);
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
        }

        return json_encode($arr);
    }

    function RemoveMeshFromDrawer()
    {
        $this->checkUser(true);

        $MeshUID = $this->getCleanValueFromArguments('MeshUID', true);
        $isToyDesigner = $this->getCleanValueFromArguments('IsToyDesigner') == 1;

        $sql = "";
        if($isToyDesigner)
        {
            $sql = "delete from \"MeshDrawerToyDesigner\" where \"MeshUID\"='$MeshUID' and \"UserUID\"='".$this->currentUserId."'";
        }
        else
        {
            $sql = "select \"OwnerUID\" from \"Mesh\" where \"MeshUID\"='$MeshUID'";
            $ownerUID = $this->db->fetchValue($sql);

            if ($ownerUID == -1)
            {
                $drawerUID = $this->db->fetchValue("select \"MeshDrawerUID\" from \"MeshDrawer\" where \"MeshUID\" = '$MeshUID' and \"UserUID\" = '".$this->currentUserId."'");
                if ($drawerUID)
                    $sql = "update \"MeshDrawer\" set \"WasRemoved\" = true where \"MeshUID\" = '$MeshUID' and \"UserUID\" = '".$this->currentUserId."'";
                else
                    $sql = "insert into \"MeshDrawer\" (\"MeshUID\", \"UserUID\", \"WasRemoved\") values ('$MeshUID', '".$this->currentUserId."', true)";
            }
            else
            {
                $sql = "delete from \"MeshDrawer\" where \"MeshUID\"='$MeshUID' and \"UserUID\"='".$this->currentUserId."'";
            }
        }

        $queryResult = $this->db->exesql($sql);
        $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
        $arr["MeshUID"] = $MeshUID;

        return json_encode($arr);
    }

//    function ReplaceMeshTemplate()
//    {
//        $this->checkUser(true);
//
//        $previousMeshUID = $this->getCleanValueFromArguments('PreviousMeshUID', true);
//        $currentMeshUID = $this->getCleanValueFromArguments('CurrentMeshUID', true);
//        $switchTemplates = $this->getCleanValueFromArguments('Switch');
//
//        $sql = "select \"MeshTemplateUID\" from \"MeshTemplates\" where \"MeshUID\"='?previous_Id?' and \"UserUID\"='?my_Id?'";
//        $sql = str_replace("?previous_Id?", $previousMeshUID , $sql);
//        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
//        $templateUID = $this->db->fetchValue($sql);
//        if (!$templateUID)
//            die($this->JsonError("There is no shape template with that ID"));
//
//        $sql = "update \"MeshTemplates\" set \"MeshUID\"='?current_Id?' where \"MeshTemplateUID\"='$templateUID'";
//        $sql = str_replace("?current_Id?", $currentMeshUID, $sql);
//
//        if ($switchTemplates == 1)
//        {
//            $secondSql = "update \"MeshTemplates\" set \"MeshUID\"='?current_Id?' where \"MeshUID\"='?previous_Id?' and \"UserUID\"='?my_Id?'";
//            $secondSql = str_replace("?current_Id?", $previousMeshUID, $secondSql);
//            $secondSql = str_replace("?previous_Id?", $currentMeshUID , $secondSql);
//            $secondSql = str_replace("?my_Id?", $this->currentUserId, $secondSql);
//
//            $queryResult = $this->db->exesql($secondSql);
//            $arr["switched"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
//        }
//        $queryResult = $this->db->exesql($sql);
//        $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
//
//        return json_encode($arr);
//    }

    function IncrementMeshUseCount()
    {
        $this->checkUser(true);

        $MeshUID = $this->getCleanValueFromArguments('MeshUID', true);

        $sql = "update \"Mesh\" set \"UseCount\"=\"UseCount\" + 1 where \"MeshUID\"='?mesh_Id?' returning \"UseCount\"";
        $sql = str_replace("?mesh_Id?", $MeshUID, $sql);
        $ret = $this->db->fetchValue($sql);

        $result["MeshUID"] = $MeshUID;
        if ($ret)
        {
            $result["UseCount"] = $ret;
            $result["result"] = 1;
        }
        else
        {
            $result["result"] = 0;
        }

        return json_encode($result);
    }

    function MakeMeshesPublic()
    {
        $this->checkUser(true);

        $meshIDs = $this->getCleanValueFromArguments('MeshIDs', true);
        $meshArray = explode(',', $meshIDs);
        foreach ($meshArray as &$singleID)
        {
            $singleID = "'".$singleID."'";
        }
        unset($singleID);
        $meshIDs = implode(',', $meshArray);

        $sql = "update \"Mesh\" set \"IsPublic\"='true' where \"MeshUID\" in ($meshIDs) and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $queryResult = $this->db->exesql($sql);

        $result["MeshIDs"] = $this->getCleanValueFromArguments('MeshIDs', true);
        $result["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;

        return json_encode($result);
    }

    function AddGroup()
    {
        $this->checkUser(true);

        $GroupUID = $this->getCleanValueFromArguments('GroupUID', true);

        $sql = "select count(\"GroupUID\") as final_count from \"Group\" where \"GroupUID\"='?group_Id?'";
        $sql = str_replace("?group_Id?", $GroupUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count > 0)
        {
            return $this->EditGroup();
        }

        $sql = "insert into \"Group\" (\"GroupUID\", \"UserUID\", \"CreatorUID\", \"Data\", \"ModificationDate\", \"DisplayName\", \"IsPublic\") values ('?group_Id?', '?user_Id?', '?creator_Id?', decode('?data?', 'base64'), '?modificationDate?', '?name?', '?is_public?')";
        $sql = str_replace("?user_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?creator_Id?", $this->getCleanValueFromArguments('CreatorUID'), $sql);
        $sql = str_replace("?group_Id?", $GroupUID, $sql);
        $sql = str_replace("?name?", $this->getCleanValueFromArguments('DisplayName'), $sql);
        $sql = str_replace("?is_public?", $this->getCleanValueFromArguments('IsPublic'), $sql);
        $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);
        $sql = str_replace("?data?", $this->getCleanValueFromArguments('Data', true), $sql);

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) == 0)
        {
            // need to find out the reason and handle the error somehow (is there a chance the GroupUID already existis in the table?)
            die($this->JsonError("Unknown error has occurred while trying to add new error", 'ServerMessage34'));
        }
        else
        {
            # add tags to group
            $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
            foreach ($tagArray as $singleTag)
            {
                if (trim($singleTag) != '')
                {
                    $this->AddSingleTagToGroup($singleTag, $GroupUID);
                }
            }

            if ($this->getCleanValueFromArguments('IsInDrawer') == 1)
            {
                $sql = "insert into \"GroupDrawer\" (\"GroupUID\", \"UserUID\") values ('?group_Id?', '?my_Id?')";
                $sql = str_replace("?group_Id?", $GroupUID, $sql);
                $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

                $this->db->exesql($sql);
            }
        }

        $result["GroupUID"] = $GroupUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function EditGroup()
    {
        $this->checkUser(true);

        $GroupUID = $this->getCleanValueFromArguments('GroupUID', true);

        $sql = "update \"Group\" set (\"ModificationDate\", \"DisplayName\", \"IsPublic\") = ('?modificationDate?', '?name?', '?is_public?') where \"GroupUID\" = '?group_Id?' and \"UserUID\" = '?my_Id?' ";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?group_Id?", $GroupUID, $sql);
        $sql = str_replace("?name?", $this->getCleanValueFromArguments('DisplayName'), $sql);
        $sql = str_replace("?is_public?", $this->getCleanValueFromArguments('IsPublic'), $sql);
        $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) == 0)
        {
            // need to find out the reason and handle the error
            die($this->JsonError("Unknown error has occurred while trying to edit a group", 'ServerMessage35'));
        }
        else
        {
            # remove old tags from group
            $this->db->exesql("delete from \"GroupTag\" where \"GroupUID\"='$GroupUID'");

            # add new tags to group
            $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
            foreach ($tagArray as $singleTag)
            {
                if (trim($singleTag) != '')
                {
                    $this->AddSingleTagToGroup($singleTag, $GroupUID);
                }
            }
        }

        $result["GroupUID"] = $GroupUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function AddGroupTags()
    {
        $this->checkUser(true);

        $GroupUID = $this->getCleanValueFromArguments('GroupUID', true);

        # add new tags to group
        $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
        foreach ($tagArray as $singleTag)
        {
            if (trim($singleTag) != '')
            {
                $this->AddSingleTagToGroup($singleTag, $GroupUID);
            }
        }

        $result["GroupUID"] = $GroupUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function DeleteGroup()
    {
        $this->checkUser(true);

        $GroupUID = $this->getCleanValueFromArguments('GroupUID', true);

        $sql = "delete from \"Group\" where \"GroupUID\"='?group_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?group_Id?", $GroupUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

        # delete from social db
        $queryResult = $this->db->exesql($sql);
        $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
        $arr["GroupUID"] = $GroupUID;
        if ($arr["result"] == 1)
        {
            # remove group tags
            $this->db->exesql("delete from \"GroupTag\" where \"GroupUID\"='$GroupUID'");

            $this->RemoveGroupFromDrawer();
        }

        return json_encode($arr);
    }

    function GetOwnedGroups()
    {
        $this->checkUser(true);

        $sql = "select \"GroupUID\", \"CreatorUID\", \"DisplayName\", \"UseCount\", \"IsPublic\", \"ModificationDate\", encode(\"Data\", 'base64') from \"Group\" where \"UserUID\"='?user_Id?'";
        $sql = str_replace("?user_Id?", $this->currentUserId, $sql);
        $groups = $this->db->sqlToArray($sql);

        if ($groups)
        {
            for ($i=0; $i < count($groups); $i++)
            {
                $groups[$i]['GroupTags'] = $this->GetGroupTags($groups[$i]['GroupUID']);
            }
            $arr["groups"] = $groups;
            $arr["result"] = 1;
        }
        else
        {
            $arr["result"] = 0;
        }

        return json_encode($arr);
    }

    function GetMissingGroups()
    {
        $groupIDs = $this->getCleanValueFromArguments('GroupIDs', true);
        $groupArray = explode(',', $groupIDs);
        foreach ($groupArray as &$singleID)
        {
            $singleID = "'".$singleID."'";
        }
        unset($singleID);
        $groupIDs = implode(',', $groupArray);

        $sql = "select g.\"GroupUID\", g.\"UserUID\", g.\"CreatorUID\", g.\"DisplayName\", g.\"UseCount\", g.\"IsPublic\", g.\"ModificationDate\", u.\"UserName\" as \"OwnerName\", encode(g.\"Data\", 'base64') from \"Group\" g left join \"User\" u on u.\"UserUID\" = g.\"UserUID\" where g.\"GroupUID\" in ($groupIDs)";
        $groups = $this->db->sqlToArray($sql);

        if ($groups)
        {
            for ($i=0; $i < count($groups); $i++)
            {
                $groups[$i]['GroupTags'] = $this->GetGroupTags($groups[$i]['GroupUID']);
            }
            $resultArray["groups"] = $groups;
            $resultArray["result"] = 1;
        }
        else
        {
            $resultArray["result"] = 0;
        }

        return json_encode($resultArray);
    }

    function GetMatchingGroups()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $limit = $this->getCleanValueFromArguments('Limit');
        $offset = $this->getCleanValueFromArguments('Offset');
        $keywords = $this->getCleanValueFromArguments('Keywords');
        $getOwnedGroups = $this->getCleanValueFromArguments('Owned');
        $skipItemsInDrawer = $this->getCleanValueFromArguments('SkipInDrawer');

        $tagsArray = array_filter(explode(' ', $keywords));
        $groupIdsString = "";
        if(count($tagsArray) > 0)
        {
            $idArray = $this->GetItemIdsByTags($tagsArray, "Group");
            $groupIdsString = implode(',', $idArray);
        }

        $sql = "select g.\"GroupUID\", g.\"UserUID\", g.\"CreatorUID\", g.\"DisplayName\", g.\"UseCount\", g.\"IsPublic\", g.\"ModificationDate\", u.\"UserName\" as \"OwnerName\", encode(g.\"Data\", 'base64') from \"Group\" g left join \"User\" u on u.\"UserUID\" = g.\"UserUID\"";
        if ($getOwnedGroups == 1)
        {
            $sql = $sql . " where g.\"UserUID\" = '$this->currentUserId'";
        }
        else
        {
            $sql = $sql . " where (g.\"IsPublic\" = 't' or g.\"UserUID\" = '$this->currentUserId')";
        }
        if ($isUserLoggedIn && $skipItemsInDrawer == 1)
        {
            $results = $this->db->exesql("select \"GroupUID\" from \"GroupDrawer\" where \"UserUID\"='$this->currentUserId'");
            $itemsInDrawerIdArray = array();
            while($line = pg_fetch_array($results))
            {
                $itemsInDrawerIdArray[] = "'".$line["GroupUID"]."'";
            }

            $itemsInDrawerIdString = implode(',', $itemsInDrawerIdArray);
            if ($itemsInDrawerIdString != "")
            {
                $sql = $sql . " and g.\"GroupUID\" not in ($itemsInDrawerIdString)";
            }
		}
		if ($groupIdsString != "")
        {
            $sql = $sql . " and g.\"GroupUID\" in ($groupIdsString) union " . $sql;
        }
        $sql = $sql . " and g.\"DisplayName\" ILIKE '%$keywords%' order by \"UseCount\" desc, \"GroupUID\" desc limit $limit offset $offset";

        $groups = $this->db->sqlToArray($sql);

        if ($groups)
        {
            for ($i=0; $i < count($groups); $i++)
            {
                $groups[$i]['GroupTags'] = $this->GetGroupTags($groups[$i]['GroupUID']);
            }
            $resultArray["groups"] = $groups;
            $resultArray["result"] = 1;
        }
        else
        {
            $resultArray["result"] = 0;
        }

        return json_encode($resultArray);
    }

    function AddGroupToDrawer()
    {
        $this->checkUser(true);

        $GroupUID = $this->getCleanValueFromArguments('GroupUID', true);
        $arr["GroupUID"] = $GroupUID;

        // don't do anything if the group doesn't exist
        $sql = "select count(\"GroupUID\") as final_count from \"Group\" where \"GroupUID\"='?group_Id?'";
        $sql = str_replace("?group_Id?", $GroupUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["msg"] = "Group was not found in the database";
            $arr["msgKey"] = 'ServerMessage101';
            $arr["result"] = 0;

            return json_encode($arr);
        }

        $arr["result"] = 1;

        if ($this->IsGroupInDrawer($GroupUID) == 0)
        {
            $sql = "insert into \"GroupDrawer\" (\"GroupUID\", \"UserUID\") values ('?group_Id?', '?my_Id?')";
            $sql = str_replace("?group_Id?", $GroupUID, $sql);
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
        }

        return json_encode($arr);
    }

    function RemoveGroupFromDrawer()
    {
        $this->checkUser(true);

        $GroupUID = $this->getCleanValueFromArguments('GroupUID', true);

        $sql = "delete from \"GroupDrawer\" where \"GroupUID\"='?group_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?group_Id?", $GroupUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

        $queryResult = $this->db->exesql($sql);
        $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
        $arr["GroupUID"] = $GroupUID;

        return json_encode($arr);
    }

    function ReplaceGroupTemplate()
    {
        $this->checkUser(true);

        $previousGroupUID = $this->getCleanValueFromArguments('PreviousGroupUID', true);
        $currentGroupUID = $this->getCleanValueFromArguments('CurrentGroupUID', true);
        $switchTemplates = $this->getCleanValueFromArguments('Switch');

        $sql = "select \"GroupTemplateUID\" from \"GroupTemplates\" where \"GroupUID\"='?previous_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?previous_Id?", $previousGroupUID , $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $templateUID = $this->db->fetchValue($sql);
        if (!$templateUID)
            die($this->JsonError("There is no group template with that ID", 'ServerMessage36'));

        $sql = "update \"GroupTemplates\" set \"GroupUID\"='?current_Id?' where \"GroupTemplateUID\"='$templateUID'";
        $sql = str_replace("?current_Id?", $currentGroupUID, $sql);

        if ($switchTemplates == 1)
        {
            $secondSql = "update \"GroupTemplates\" set \"GroupUID\"='?current_Id?' where \"GroupUID\"='?previous_Id?' and \"UserUID\"='?my_Id?'";
            $secondSql = str_replace("?current_Id?", $previousGroupUID, $secondSql);
            $secondSql = str_replace("?previous_Id?", $currentGroupUID , $secondSql);
            $secondSql = str_replace("?my_Id?", $this->currentUserId, $secondSql);

            $queryResult = $this->db->exesql($secondSql);
            $arr["switched"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
        }
        $queryResult = $this->db->exesql($sql);
        $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;

        return json_encode($arr);
    }

    function IncrementGroupUseCount()
    {
        $this->checkUser(true);

        $GroupUID = $this->getCleanValueFromArguments('GroupUID', true);

        $sql = "update \"Group\" set \"UseCount\"=\"UseCount\" + 1 where \"GroupUID\"='?group_Id?' returning \"UseCount\"";
        $sql = str_replace("?group_Id?", $GroupUID, $sql);
        $ret = $this->db->fetchValue($sql);

        $result["GroupUID"] = $GroupUID;
        if ($ret)
        {
            $result["UseCount"] = $ret;
            $result["result"] = 1;
        }
        else
        {
            $result["result"] = 0;
        }

        return json_encode($result);
    }

    function MakeGroupsPublic()
    {
        $this->checkUser(true);

        $groupIDs = $this->getCleanValueFromArguments('GroupIDs', true);
        $groupArray = explode(',', $groupIDs);
        foreach ($groupArray as &$singleID)
        {
            $singleID = "'".$singleID."'";
        }
        unset($singleID);
        $groupIDs = implode(',', $groupArray);

        $sql = "update \"Group\" set \"IsPublic\"='true' where \"GroupUID\" in ($groupIDs) and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $queryResult = $this->db->exesql($sql);

        $result["GroupIDs"] = $this->getCleanValueFromArguments('GroupIDs', true);
        $result["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;

        return json_encode($result);
    }

    function UpdateSwatch()
    {
        $this->checkUser(true);

        $SwatchUID = $this->getCleanValueFromArguments('SwatchUID', true);

        $arr['TextureUID'] = $this->getCleanValueFromArguments('TextureUID');
        $arr['Color'] = $this->getCleanValueFromArguments('Color');
        $arr['Color2'] = $this->getCleanValueFromArguments('Color2');
        $arr['Gradient'] = $this->getCleanValueFromArguments('Gradient');
        $arr['TexGradient'] = $this->getCleanValueFromArguments('TexGradient');
        $arr['OutlineColor'] = $this->getCleanValueFromArguments('OutlineColor');
        $arr['Outline'] = $this->getCleanValueFromArguments('Outline');
        $arr['Bound'] = $this->getCleanValueFromArguments('Bound');
        $arr['TexBound'] = $this->getCleanValueFromArguments('TexBound');
        $arr['GradStyle'] = $this->getCleanValueFromArguments('GradStyle');
        $arr['TexGradStyle'] = $this->getCleanValueFromArguments('TexGradStyle');
        $arr['TexOffsetX'] = $this->getCleanValueFromArguments('TexOffsetX');
        $arr['TexOffsetY'] = $this->getCleanValueFromArguments('TexOffsetY');
        $arr['TexScaleX'] = $this->getCleanValueFromArguments('TexScaleX');
        $arr['TexScaleY'] = $this->getCleanValueFromArguments('TexScaleY');
        if (isset($this->arguments['IsVideo']))
        {
            $arr['IsVideo'] = $this->getCleanValueFromArguments('IsVideo');
        }

        $this->db->UpdateAndReturnJson("Swatches", $arr, " where \"SwatchUID\"='$SwatchUID' and \"UserUID\"='$this->currentUserId'");

        $result["SwatchUID"] = $SwatchUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function AddTexture()
    {
        $this->checkUser(true);

        $TextureUID = $this->getCleanValueFromArguments('TextureUID', true);

        $sql = "select count(\"TextureUID\") as final_count from \"Texture\" where \"TextureUID\"='?texture_Id?'";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count > 0)
        {
            die($this->JsonError("Texture with that ID already exists", 'ServerMessage37'));
        }

        $textureUrl = '';
        $hiResTextureUrl = '';
        $thumbnailUrl = '';

        if (count($_FILES) > 0 && $_FILES['TextureData']['error'] == 0)
        {
            $isHiResTextue = $this->getCleanValueFromArguments('IsHiResTexture') == 1;
            $fileHandler = new FileHandler();

            if ($isHiResTextue)
            {
                $fileRelativePath = 'img/texture/highres/' . time() . '-' . $TextureUID . '.png';

                $hiResTextureUrl = $fileHandler->moveFile($_FILES['TextureData']['tmp_name'], $fileRelativePath);
                if ($hiResTextureUrl == '')
                {
                    die($this->JsonError("Failed to save texture file", 'ServerMessage38'));
                }
                else
                {
                    $fileRelativePath = 'img/texture/' . time() . '-' . $TextureUID . '.png';

                    $textureUrl = $fileHandler->createResizedTexture($textureUrl, $fileRelativePath, 2048);
                    if ($textureUrl == '')
                    {
                        FileHandler::deleteImageFile($hiResTextureUrl);
                        die($this->JsonError("Failed to save texture file", 'ServerMessage38'));
                    }
                }
            }
            else
            {
                $fileRelativePath = 'img/texture/' . time() . '-' . $TextureUID . '.png';

                $textureUrl = $fileHandler->moveFile($_FILES['TextureData']['tmp_name'], $fileRelativePath);
                if ($textureUrl == '')
                {
                    die($this->JsonError("Failed to save texture file", 'ServerMessage38'));
                }
            }

            $fileRelativePath = 'img/texture/thumbnail/' . time() . '-' . $TextureUID . '.png';
            if (isset($_FILES['ThumbnailData']) && is_uploaded_file($_FILES['ThumbnailData']['tmp_name']) && $_FILES['ThumbnailData']['error'] == 0)
            {
                $thumbnailUrl = $fileHandler->moveFile($_FILES['ThumbnailData']['tmp_name'], $fileRelativePath);
            }
            if ($thumbnailUrl == '')
            {
                $thumbnailUrl = $fileHandler->createResizedTexture($textureUrl, $fileRelativePath, 64);
            }
        }
        else
        {
            die($this->JsonError("Failed to upload texture file", 'ServerMessage39'));
        }

        $sql = "insert into \"Texture\" (\"TextureUID\", \"OwnerUID\", \"TextureUrl\", \"ThumbnailUrl\", \"HiResUrl\", \"DisplayName\", \"IsPublic\", \"ModificationDate\") values ('?texture_Id?', '?user_Id?', '?location?', '?thumbnail_location?', '?hiRes_location?', '?name?', '?is_public?', '?modificationDate?')";
        $sql = str_replace("?user_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $sql = str_replace("?name?", $this->getCleanValueFromArguments('DisplayName'), $sql);
        $sql = str_replace("?location?", $textureUrl, $sql);
        $sql = str_replace("?thumbnail_location?", $thumbnailUrl, $sql);
        $sql = str_replace("?hiRes_location?", $hiResTextureUrl, $sql);
        $sql = str_replace("?is_public?", $this->getCleanValueFromArguments('IsPublic'), $sql);
        $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) == 0)
        {
            // need to find out the reason and handle the error somehow (is there a chance the TextureUID already existis in the table?)
            FileHandler::deleteImageFile($textureUrl);
            if ($hiResTextureUrl != '')
                FileHandler::deleteImageFile($hiResTextureUrl);
            if ($thumbnailUrl != '')
                FileHandler::deleteImageFile($thumbnailUrl);
            die($this->JsonError("Unknown error has occurred while trying to add new texture", 'ServerMessage40'));
        }
        else
        {
            # add tags to group
            $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
            foreach ($tagArray as $singleTag)
            {
                if (trim($singleTag) != '')
                {
                    $this->AddSingleTagToTexture($singleTag, $TextureUID);
                }
            }

            if ($this->getCleanValueFromArguments('IsInDrawer') == 1)
            {
                $sql = "insert into \"TextureDrawer\" (\"TextureUID\", \"UserUID\") values ('?texture_Id?', '?my_Id?')";
                $sql = str_replace("?texture_Id?", $TextureUID, $sql);
                $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

                $this->db->exesql($sql);
            }
        }
        
        $result["TextureUID"] = $TextureUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function SetTextureThumbnail()
    {
        $this->checkUser(true);

        $TextureUID = $this->getCleanValueFromArguments('TextureUID', true);

        $sql = "select count(\"TextureUID\") as final_count from \"Texture\" where \"TextureUID\"='?texture_Id?' and \"OwnerUID\" = '?my_Id?'";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            die($this->JsonError("There is no texture with that ID or it is owned by some other user", 'ServerMessage41'));
        }

        $thumbnailUrl = '';

        if (count($_FILES) > 0 && is_uploaded_file($_FILES['ThumbnailData']['tmp_name']) && $_FILES['ThumbnailData']['error'] == 0)
        {
            $fileRelativePath = 'img/texture/thumbnail/' . time() . '-' . $TextureUID . '.png';

            $fileHandler = new FileHandler();
            $thumbnailUrl = $fileHandler->moveFile($_FILES['ThumbnailData']['tmp_name'], $fileRelativePath);
            if ($thumbnailUrl == '')
            {
                die($this->JsonError("Failed to save texture thumbnail file", 'ServerMessage42'));
            }
        }
        else
        {
            die($this->JsonError("Failed to upload texture thumbnail file", 'ServerMessage43'));
        }

        $sql = "update \"Texture\" set (\"ThumbnailUrl\") values ('?thumbnail_location?') where \"TextureUID\" = '?texture_Id?' and \"OwnerUID\" = '?my_Id?'";
        $sql = str_replace("?user_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $sql = str_replace("?thumbnail_location?", $thumbnailUrl, $sql);

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) == 0)
        {
            // need to find out the reason and handle the error somehow (is there a chance the TextureUID already existis in the table?)
            FileHandler::deleteImageFile($thumbnailUrl);
            die($this->JsonError("Failed to update texture thumbnail info", 'ServerMessage44'));
        }

        $result["TextureUID"] = $TextureUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    private function GenerateMissingThumbnails()
    {
        // designs
        $sql = "select \"DesignUID\", \"PictureUrl\" from \"Design\" where \"PictureUrl\" != '' and  \"ThumbnailUrl\" = '' ";
        $designs = $this->db->sqlToArray($sql);
        if ($designs)
        {
            $fileHandler = new FileHandler();
            for ($i=0; $i < count($designs); $i++)
            {
                $DesignUID = $designs[$i]['DesignUID'];
                $fileRelativePath = 'img/design/thumbnail/' . $DesignUID . '.jpg';
                $thumbnailUrl = $fileHandler->createResizedTexture($designs[$i]['PictureUrl'], $fileRelativePath, 208);

                if ($thumbnailUrl != '')
                {
                    $sql = "update \"Design\" set \"ThumbnailUrl\" = '?thumbnail_location?' where \"DesignUID\" = '?design_Id?'";
                    $sql = str_replace("?design_Id?", $DesignUID, $sql);
                    $sql = str_replace("?thumbnail_location?", $thumbnailUrl, $sql);

                    $queryResult = $this->db->exesql($sql);
                    if (pg_affected_rows($queryResult) == 0)
                    {
                        // updating the row has failed
                        FileHandler::deleteImageFile($thumbnailUrl);
                    }
                }
            }
        }

        // textures
        $sql = "select \"TextureUID\", \"TextureUrl\" from \"Texture\" where \"TextureUrl\" != '' and  \"ThumbnailUrl\" = '' ";
        $textures = $this->db->sqlToArray($sql);
        if ($textures)
        {
            $fileHandler = new FileHandler();
            for ($i=0; $i < count($textures); $i++)
            {
                $TextureUID = $textures[$i]['TextureUID'];
                $fileRelativePath = 'img/texture/thumbnail/' . time() . '-' . $TextureUID . '.png';
                $thumbnailUrl = $fileHandler->createResizedTexture($textures[$i]['TextureUrl'], $fileRelativePath, 64);

                if ($thumbnailUrl != '')
                {
                    $sql = "update \"Texture\" set \"ThumbnailUrl\" = '?thumbnail_location?' where \"TextureUID\" = '?texture_Id?'";
                    $sql = str_replace("?texture_Id?", $TextureUID, $sql);
                    $sql = str_replace("?thumbnail_location?", $thumbnailUrl, $sql);

                    $queryResult = $this->db->exesql($sql);
                    if (pg_affected_rows($queryResult) == 0)
                    {
                        // updating the row has failed
                        FileHandler::deleteImageFile($thumbnailUrl);
                    }
                }
            }
        }
    }

    function EditTexture()
    {
        $this->checkUser(true);

        $TextureUID = $this->getCleanValueFromArguments('TextureUID', true);

        $sql = "update \"Texture\" set (\"ModificationDate\", \"DisplayName\") = ('?modificationDate?', '?name?') where \"TextureUID\" = '?texture_Id?' and \"OwnerUID\" = '?my_Id?' ";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $sql = str_replace("?name?", $this->getCleanValueFromArguments('DisplayName'), $sql);
        $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) == 0)
        {
            // need to find out the reason and handle the error
            die($this->JsonError("Unknown error has occurred while trying to edit a texture", 'ServerMessage45'));
        }
        else
        {
            # remove old tags from texture
            $this->db->exesql("delete from \"TextureTag\" where \"TextureUID\"='$TextureUID'");

            # add new tags to texture
            $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
            foreach ($tagArray as $singleTag)
            {
                if (trim($singleTag) != '')
                {
                    $this->AddSingleTagToTexture($singleTag, $TextureUID);
                }
            }
        }

        $result["TextureUID"] = $TextureUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function AddTextureTags()
    {
        $this->checkUser(true);

        $TextureUID = $this->getCleanValueFromArguments('TextureUID', true);

        # add new tags to texture
        $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
        foreach ($tagArray as $singleTag)
        {
            if (trim($singleTag) != '')
            {
                $this->AddSingleTagToTexture($singleTag, $TextureUID);
            }
        }

        $result["TextureUID"] = $TextureUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function DeleteTexture()
    {
        $this->checkUser(true);

        $TextureUID = $this->getCleanValueFromArguments('TextureUID', true);

        # get texture image path
        $sql = "select \"TextureUrl\" from \"Texture\" where \"TextureUID\"='?texture_Id?' and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $textureUrl = $this->db->fetchValue($sql);

        # get texture thumbnail path
        $sql = "select \"ThumbnailUrl\" from \"Texture\" where \"TextureUID\"='?texture_Id?' and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $thumbnailUrl = $this->db->fetchValue($sql);
        
        # get hi-res texture path
        $sql = "select \"HiResUrl\" from \"Texture\" where \"TextureUID\"='?texture_Id?' and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $hiResTextureUrl = $this->db->fetchValue($sql);

        # remove texture from all drawers
        $sql = "delete from \"TextureDrawer\" where \"TextureUID\"='?texture_Id?'";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $this->db->exesql($sql);

        #remove texture from all swatches
        $sql = "update \"Swatches\" set \"TextureUID\"='' where \"TextureUID\"='?texture_Id?'";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $this->db->exesql($sql);

        #remove texture from db
        $sql = "delete from \"Texture\" where \"TextureUID\"='?texture_Id?' and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

        # delete from social db
        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) > 0)
        {
            $arr["result"] = 1;

            # remove image file
            if ($textureUrl && $textureUrl != '')
                FileHandler::deleteImageFile($textureUrl);

            if ($thumbnailUrl && $thumbnailUrl != '')
                FileHandler::deleteImageFile($thumbnailUrl);
                
            if ($hiResTextureUrl && $hiResTextureUrl != '')
                FileHandler::deleteImageFile($hiResTextureUrl);

            # remove texture tags
            $this->db->exesql("delete from \"TextureTag\" where \"TextureUID\"='$TextureUID'");
        }
        else
        {
            $arr["result"] = 0;
        }
        $arr["TextureUID"] = $TextureUID;

        return json_encode($arr);
    }

    function GetOwnedTextures()
    {
        $this->checkUser(true);

        $sql = "select \"TextureUID\", \"DisplayName\", \"UseCount\", \"IsPublic\", \"ModificationDate\", \"TextureUrl\", \"ThumbnailUrl\", \"HiResUrl\" from \"Texture\" where \"OwnerUID\"='?user_Id?'";
        $sql = str_replace("?user_Id?", $this->currentUserId, $sql);
        $textures = $this->db->sqlToArray($sql);

        if ($textures)
        {
            for ($i=0; $i < count($textures); $i++)
            {
                $textures[$i]['TextureTags'] = $this->GetTextureTags($textures[$i]['TextureUID']);
            }
            $arr["textures"] = $textures;
            $arr["result"] = 1;
        }
        else
        {
            $arr["result"] = 0;
        }

        return json_encode($arr);
    }

    function GetMissingTextures()
    {
        //$this->checkUser(true);

        $textureIDs = $this->getCleanValueFromArguments('TextureIDs', true);
        $textureArray = explode(',', $textureIDs);
        $texturesFound = array();
        $texturesMissing = array();
        foreach ($textureArray as &$singleID)
        {
            $sql = "select count(\"TextureUID\") as final_count from \"Texture\" where \"TextureUID\"='$singleID'";
            $count = $this->db->fetchValue($sql);
            if($count == 0)
            {
                $texturesMissing[] = $singleID;
            }
            else
            {
                $texturesFound[] = "'".$singleID."'";
            }
        }
        unset($singleID);

        $resultArray["DesignUID"] = $this->getCleanValueFromArguments('DesignUID', true);
        $texturesSet = true;

        if (count($texturesFound) > 0)
        {
            $textureIDs = implode(',', $texturesFound);

            $sql = "select t.\"TextureUID\", t.\"DisplayName\", t.\"UseCount\", t.\"OwnerUID\", t.\"IsPublic\", t.\"ModificationDate\", t.\"TextureUrl\", t.\"ThumbnailUrl\", t.\"HiResUrl\", u.\"UserName\" as \"OwnerName\" from \"Texture\" t left join \"User\" u on u.\"UserUID\" = t.\"OwnerUID\" where t.\"TextureUID\" in ($textureIDs)";
            $textures = $this->db->sqlToArray($sql);

            if ($textures)
            {
                for ($i=0; $i < count($textures); $i++)
                {
                    $textures[$i]['TextureTags'] = $this->GetTextureTags($textures[$i]['TextureUID']);
                }
                $resultArray["textures"] = $textures;
            }
            else
            {
                $texturesSet = false;
            }
        }
        if (count($texturesMissing) > 0)
        {
            $textureIDs = implode(',', $texturesMissing);

            $subject = "Missing textures";
            $message = "Design ID: " . $resultArray["DesignUID"] . "<br/>Texture IDs: " . $textureIDs;
            $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');

            $resultArray["missingTextures"] = $textureIDs;
        }

        if ($texturesSet)
        {
            $resultArray["result"] = 1;
        }
        else
        {
            $resultArray["result"] = 0;
        }

        return json_encode($resultArray);
    }

    function GetMatchingTextures()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $limit = $this->getCleanValueFromArguments('Limit');
        $offset = $this->getCleanValueFromArguments('Offset');
        $keywords = $this->getCleanValueFromArguments('Keywords');
        $getOwnedTextures = $this->getCleanValueFromArguments('Owned');
        $skipItemsInDrawer = $this->getCleanValueFromArguments('SkipInDrawer');

        $tagsArray = array_filter(explode(' ', $keywords));
        $textureIdsString = "";
        if(count($tagsArray) > 0)
        {
            $idArray = $this->GetItemIdsByTags($tagsArray, "Texture");
            $textureIdsString = implode(',', $idArray);
        }

        $sql = "select t.\"TextureUID\", t.\"DisplayName\", t.\"UseCount\", t.\"OwnerUID\", t.\"IsPublic\", t.\"ModificationDate\", t.\"TextureUrl\", t.\"ThumbnailUrl\", t.\"HiResUrl\", u.\"UserName\" as \"OwnerName\" from \"Texture\" t left join \"User\" u on u.\"UserUID\" = t.\"OwnerUID\"";
        if ($getOwnedTextures == 1)
        {
            $sql = $sql . " where t.\"OwnerUID\" = '$this->currentUserId'";
        }
        else
        {
            $sql = $sql . " where (t.\"IsPublic\" = 't' or t.\"OwnerUID\" = '$this->currentUserId')";
        }
        if ($isUserLoggedIn && $skipItemsInDrawer == 1)
        {
            $results = $this->db->exesql("select \"TextureUID\" from \"TextureDrawer\" where \"UserUID\"='$this->currentUserId'");
            $itemsInDrawerIdArray = array();
            while($line = pg_fetch_array($results))
            {
                $itemsInDrawerIdArray[] = "'".$line["TextureUID"]."'";
            }

            $itemsInDrawerIdString = implode(',', $itemsInDrawerIdArray);
            if ($itemsInDrawerIdString != "")
            {
                $sql = $sql . " and t.\"TextureUID\" not in ($itemsInDrawerIdString)";
            }
        }
        if ($textureIdsString != "")
        {
            $sql = $sql . " and t.\"TextureUID\" in ($textureIdsString) union " . $sql;
        }
        $sql = $sql . " and t.\"DisplayName\" ILIKE '%$keywords%' order by \"UseCount\" desc, \"TextureUID\" desc limit $limit offset $offset";

        $textures = $this->db->sqlToArray($sql);

        if ($textures)
        {
            for ($i=0; $i < count($textures); $i++)
            {
                $textures[$i]['TextureTags'] = $this->GetTextureTags($textures[$i]['TextureUID']);
            }
            $resultArray["textures"] = $textures;
            $resultArray["result"] = 1;
        }
        else
        {
            $resultArray["result"] = 0;
        }

        return json_encode($resultArray);
    }

    function AddTextureToDrawer()
    {
        $this->checkUser(true);

        $TextureUID = $this->getCleanValueFromArguments('TextureUID', true);
        $arr["TextureUID"] = $TextureUID;

        // don't do anything if the texture doesn't exist
        $sql = "select count(\"TextureUID\") as final_count from \"Texture\" where \"TextureUID\"='?texture_Id?'";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["msg"] = "Texture was not found in the database";
            $arr["msgKey"] = 'ServerMessage102';
            $arr["result"] = 0;

            return json_encode($arr);
        }

        $arr["result"] = 1;

        if ($this->IsTextureInDrawer($TextureUID) == 0)
        {
            $sql = "insert into \"TextureDrawer\" (\"TextureUID\", \"UserUID\") values ('?texture_Id?', '?my_Id?')";
            $sql = str_replace("?texture_Id?", $TextureUID, $sql);
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
        }

        return json_encode($arr);
    }

    function RemoveTextureFromDrawer()
    {
        $this->checkUser(true);

        $TextureUID = $this->getCleanValueFromArguments('TextureUID', true);

        $sql = "delete from \"TextureDrawer\" where \"TextureUID\"='?texture_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

        $queryResult = $this->db->exesql($sql);
        $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
        $arr["TextureUID"] = $TextureUID;

        return json_encode($arr);
    }

    function IncrementTextureUseCount()
    {
        $this->checkUser(true);

        $TextureUID = $this->getCleanValueFromArguments('TextureUID', true);

        $sql = "update \"Texture\" set \"UseCount\"=\"UseCount\" + 1 where \"TextureUID\"='?texture_Id?' returning \"UseCount\"";
        $sql = str_replace("?texture_Id?", $TextureUID, $sql);
        $ret = $this->db->fetchValue($sql);

        $result["TextureUID"] = $TextureUID;
        if ($ret)
        {
            $result["UseCount"] = $ret;
            $result["result"] = 1;
        }
        else
        {
            $result["result"] = 0;
        }

        return json_encode($result);
    }

    function MakeTexturesPublic()
    {
        $this->checkUser(true);

        $textureIDs = $this->getCleanValueFromArguments('TextureIDs', true);
        $textureArray = explode(',', $textureIDs);
        foreach ($textureArray as &$singleID)
        {
            $singleID = "'".$singleID."'";
        }
        unset($singleID);
        $textureIDs = implode(',', $textureArray);

        $sql = "update \"Texture\" set \"IsPublic\"='true' where \"TextureUID\" in ($textureIDs) and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $queryResult = $this->db->exesql($sql);

        $result["TextureIDs"] = $this->getCleanValueFromArguments('TextureIDs', true);
        $result["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;

        return json_encode($result);
    }

	
    function AddVideo()
    {
        $this->checkUser(true);

        $VideoUID = $this->getCleanValueFromArguments('VideoUID', true);

        $sql = "select count(\"VideoUID\") as final_count from \"Video\" where \"VideoUID\"='?video_Id?'";
        $sql = str_replace("?video_Id?", $VideoUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count > 0)
        {
            die($this->JsonError("Video with that ID already exists", 'ServerMessage46'));
            //return $this->EditVideo();
        }

        if (count($_FILES) > 0 && $_FILES['VideoData']['error'] == 0)
        {
            $thumbnailUrl = 'img/video/thumbnail/' . $VideoUID . '.jpg';
            $fileRelativePath = 'img/video/' . $VideoUID . '.mp4';

            $fileHandler = new FileHandler();
            $videoUrl = $fileHandler->moveFile($_FILES['VideoData']['tmp_name'], $fileRelativePath);
            if ($videoUrl == '')
            {
                die($this->JsonError("Failed to save the video file", 'ServerMessage47'));
            }
        }
        else
        {
            die($this->JsonError("Failed to upload the video file", 'ServerMessage48'));
        }

        $displayName = $this->getCleanValueFromArguments('DisplayName');
        $isInDrawer = $this->getCleanValueFromArguments('IsInDrawer');
        $isPublic = $this->getCleanValueFromArguments('IsPublic');

        $sql = "insert into \"Video\" (\"VideoUID\", \"OwnerUID\", \"VideoUrl\", \"ThumbnailUrl\", \"DisplayName\", \"IsPublic\") values ('?video_Id?', '?user_Id?', '?location?', '?location_thumbnail?', '?name?', '?is_public?')";
        $sql = str_replace("?user_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?video_Id?", $VideoUID, $sql);
        $sql = str_replace("?name?", $displayName, $sql);
        $sql = str_replace("?location?", $videoUrl, $sql);
        $sql = str_replace("?location_thumbnail?", $thumbnailUrl, $sql);
        $sql = str_replace("?is_public?", $isPublic, $sql);

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) == 0)
        {
            // need to find out the reason and handle the error somehow (is there a chance the VideoUID already existis in the table?)
            FileHandler::deleteImageFile($videoUrl);

            die($this->JsonError("Failed to save the video into database", 'ServerMessage49'));
        }
        else
        {
            $this->CreateThumbnail($videoUrl, $thumbnailUrl);

            # add tags to video
            $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
            foreach ($tagArray as $singleTag)
            {
                if (trim($singleTag) != '')
                {
                    $this->AddSingleTagToVideo($singleTag, $VideoUID);
                }
            }

            if ($isInDrawer == 1)
            {
                $sql = "insert into \"VideoDrawer\" (\"VideoUID\", \"UserUID\") values ('?video_Id?', '?my_Id?')";
                $sql = str_replace("?video_Id?", $VideoUID, $sql);
                $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

                $this->db->exesql($sql);
            }
        }

        $result["DisplayName"] = $displayName;
        $result["IsPublic"] = strtolower($isPublic) == 'true' ? 't' : 'n';
        $result["VideoUrl"] = $videoUrl;
        $result["ThumbnailUrl"] = $thumbnailUrl;
        $result["IsInDrawer"] = $isInDrawer == 1 ? 't' : 'n';
        $result["VideoUID"] = $VideoUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    private function CreateThumbnail($video , $thumb_image)
    {
        $ffmpeg = '/usr/local/bin/ffmpeg';
        $second = 1;
        $cmd = "$ffmpeg -i \"{$video}\" -deinterlace -an -ss $second -t 00:00:01 -r 1 -y -vcodec mjpeg -f mjpeg \"{$thumb_image}\" 2>&1";
        shell_exec($cmd);
    }

/*
    function EditVideo()
    {
        $this->checkUser(true);

        $VideoUID = $this->getCleanValueFromArguments('VideoUID', true);

        $sql = "update \"Video\" set (\"ModificationDate\", \"DisplayName\") = ('?modificationDate?', '?name?') where \"VideoUID\" = '?video_Id?' and \"OwnerUID\" = '?my_Id?' ";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $sql = str_replace("?video_Id?", $VideoUID, $sql);
        $sql = str_replace("?name?", $this->getCleanValueFromArguments('DisplayName'), $sql);
        $sql = str_replace("?modificationDate?", $this->getCleanValueFromArguments('ModificationDate'), $sql);

        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) == 0)
        {
            // need to find out the reason and handle the error
            die($this->JsonError("Unknown error has occurred while trying to edit a video", 'ServerMessage107'));
        }
        else
        {
            # remove old tags from video
            $this->db->exesql("delete from \"VideoTag\" where \"VideoUID\"='$VideoUID'");

            # add new tags to video
            $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
            foreach ($tagArray as $singleTag)
            {
                if (trim($singleTag) != '')
                {
                    $this->AddSingleTagToVideo($singleTag, $VideoUID);
                }
            }
        }

        $result["VideoUID"] = $VideoUID;
        $result["result"] = 1;

        return json_encode($result);
    }

    function AddVideoTags()
    {
        $this->checkUser(true);

        $VideoUID = $this->getCleanValueFromArguments('VideoUID', true);

        # add new tags to video
        $tagArray = explode(',', $this->getCleanValueFromArguments('Tags'));
        foreach ($tagArray as $singleTag)
        {
            if (trim($singleTag) != '')
            {
                $this->AddSingleTagToVideo($singleTag, $VideoUID);
            }
        }

        $result["VideoUID"] = $VideoUID;
        $result["result"] = 1;

        return json_encode($result);
    }
*/

    function DeleteVideo()
    {
        $this->checkUser(true);

        $VideoUID = $this->getCleanValueFromArguments('VideoUID', true);

        # get video name
        $sql = "select \"VideoUrl\" from \"Video\" where \"VideoUID\"='?video_Id?' and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?video_Id?", $VideoUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $videoUrl = $this->db->fetchValue($sql);

        # get video thumbnail name
        $sql = "select \"ThumbnailUrl\" from \"Video\" where \"VideoUID\"='?video_Id?' and \"OwnerUID\"='?my_Id?'";
		$thumbnailUrl = $this->db->fetchValue($sql);

        # remove video from all drawers
        $sql = "delete from \"VideoDrawer\" where \"VideoUID\"='?video_Id?'";
        $sql = str_replace("?video_Id?", $VideoUID, $sql);
        $this->db->exesql($sql);

        #remove video from db
        $sql = "delete from \"Video\" where \"VideoUID\"='?video_Id?' and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?video_Id?", $VideoUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

        # remove files after delete
        $queryResult = $this->db->exesql($sql);
        if (pg_affected_rows($queryResult) > 0)
        {
            $arr["result"] = 1;

            # remove image file
            if ($videoUrl && $videoUrl != '')
                FileHandler::deleteImageFile($videoUrl);

            # remove image file
            if ($thumbnailUrl && $thumbnailUrl != '')
                FileHandler::deleteImageFile($thumbnailUrl);

            # remove video tags
            $this->db->exesql("delete from \"VideoTag\" where \"VideoUID\"='$VideoUID'");
        }
        else
        {
            $arr["result"] = 0;
        }
        $arr["VideoUID"] = $VideoUID;

        return json_encode($arr);
    }

    function GetOwnedVideos()
    {
        $this->checkUser(true);

        $sql = "select \"VideoUID\", \"DisplayName\", \"UseCount\", \"IsPublic\", \"VideoUrl\", \"ThumbnailUrl\" from \"Video\" where \"OwnerUID\"='?user_Id?'";
        $sql = str_replace("?user_Id?", $this->currentUserId, $sql);
        $videos = $this->db->sqlToArray($sql);

        if ($videos)
        {
            for ($i=0; $i < count($videos); $i++)
            {
                $videos[$i]['VideoTags'] = $this->GetVideoTags($videos[$i]['VideoUID']);
            }
            $arr["videos"] = $videos;
            $arr["result"] = 1;
        }
        else
        {
            $arr["result"] = 0;
        }

        return json_encode($arr);
    }

    function GetMissingVideos()
    {
        //$this->checkUser(true);

        $videoIDs = $this->getCleanValueFromArguments('VideoIDs', true);
        $videoArray = explode(',', $videoIDs);
        $videosFound = array();
        $videosMissing = array();
        foreach ($videoArray as &$singleID)
        {
            $sql = "select count(\"VideoUID\") as final_count from \"Video\" where \"VideoUID\"='$singleID'";
            $count = $this->db->fetchValue($sql);
            if($count == 0)
            {
                $videosMissing[] = $singleID;
            }
            else
            {
                $videosFound[] = "'".$singleID."'";
            }
        }
        unset($singleID);

        $resultArray["DesignUID"] = $this->getCleanValueFromArguments('DesignUID', true);
        $videosSet = true;

        if (count($videosFound) > 0)
        {
            $videoIDs = implode(',', $videosFound);

            $sql = "select v.\"VideoUID\", v.\"DisplayName\", v.\"UseCount\", v.\"OwnerUID\", v.\"IsPublic\", v.\"VideoUrl\", v.\"ThumbnailUrl\", u.\"UserName\" as \"OwnerName\" from \"Video\" v left join \"User\" u on u.\"UserUID\" = v.\"OwnerUID\" where v.\"VideoUID\" in ($videoIDs)";
            $videos = $this->db->sqlToArray($sql);

            if ($videos)
            {
                for ($i=0; $i < count($videos); $i++)
                {
                    $videos[$i]['VideoTags'] = $this->GetVideoTags($videos[$i]['VideoUID']);
                }
                $resultArray["videos"] = $videos;
            }
            else
            {
                $videosSet = false;
            }
        }
        if (count($videosMissing) > 0)
        {
            $videoIDs = implode(',', $videosMissing);

            $subject = "Missing videos";
            $message = "Design ID: " . $resultArray["DesignUID"] . "<br/>Video IDs: " . $videoIDs;
            $this->SendEmailSendGrid($this->info_email_address, $subject, $message, $this->info_email_address, $this->application_name . ' Support');

            $resultArray["missingVideos"] = $videoIDs;
        }

        if ($videosSet)
        {
            $resultArray["result"] = 1;
        }
        else
        {
            $resultArray["result"] = 0;
        }

        return json_encode($resultArray);
    }

    function GetMatchingVideos()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $limit = $this->getCleanValueFromArguments('Limit');
        $offset = $this->getCleanValueFromArguments('Offset');
        $keywords = $this->getCleanValueFromArguments('Keywords');
        $getOwnedVideos = $this->getCleanValueFromArguments('Owned');
        $skipItemsInDrawer = $this->getCleanValueFromArguments('SkipInDrawer');

        $tagsArray = array_filter(explode(' ', $keywords));
        $videoIdsString = "";
        if(count($tagsArray) > 0)
        {
            $idArray = $this->GetItemIdsByTags($tagsArray, "Video");
            $videoIdsString = implode(',', $idArray);
        }

        $sql = "select v.\"VideoUID\", v.\"DisplayName\", v.\"UseCount\", v.\"OwnerUID\", v.\"IsPublic\", v.\"VideoUrl\", v.\"ThumbnailUrl\", u.\"UserName\" as \"OwnerName\" from \"Video\" v left join \"User\" u on u.\"UserUID\" = v.\"OwnerUID\"";
        if ($getOwnedVideos == 1)
        {
            $sql = $sql . " where v.\"OwnerUID\" = '$this->currentUserId'";
        }
        else
        {
            $sql = $sql . " where (v.\"IsPublic\" = 't' or v.\"OwnerUID\" = '$this->currentUserId')";
        }
        if ($isUserLoggedIn && $skipItemsInDrawer == 1)
        {
            $results = $this->db->exesql("select \"VideoUID\" from \"VideoDrawer\" where \"UserUID\"='$this->currentUserId'");
            $itemsInDrawerIdArray = array();
            while($line = pg_fetch_array($results))
            {
                $itemsInDrawerIdArray[] = "'".$line["VideoUID"]."'";
            }

            $itemsInDrawerIdString = implode(',', $itemsInDrawerIdArray);
            if ($itemsInDrawerIdString != "")
            {
                $sql = $sql . " and v.\"VideoUID\" not in ($itemsInDrawerIdString)";
            }
        }
        if ($videoIdsString != "")
        {
            $sql = $sql . " and v.\"VideoUID\" in ($videoIdsString) union " . $sql;
        }
        $sql = $sql . " and v.\"DisplayName\" ILIKE '%$keywords%' order by \"UseCount\" desc, \"VideoUID\" desc limit $limit offset $offset";

        $videos = $this->db->sqlToArray($sql);

        if ($videos)
        {
            for ($i=0; $i < count($videos); $i++)
            {
                $videos[$i]['VideoTags'] = $this->GetVideoTags($videos[$i]['VideoUID']);
            }
            $resultArray["videos"] = $videos;
            $resultArray["result"] = 1;
        }
        else
        {
            $resultArray["result"] = 0;
        }

        return json_encode($resultArray);
    }

    function AddVideoToDrawer()
    {
        $this->checkUser(true);

        $VideoUID = $this->getCleanValueFromArguments('VideoUID', true);
        $arr["VideoUID"] = $VideoUID;

        // don't do anything if the video doesn't exist
        $sql = "select count(\"VideoUID\") as final_count from \"Video\" where \"VideoUID\"='?video_Id?'";
        $sql = str_replace("?video_Id?", $VideoUID, $sql);
        $count = $this->db->fetchValue($sql);
        if($count == 0)
        {
            $arr["msg"] = "Video was not found in the database";
            $arr["msgKey"] = 'Video was not found in the database';
            $arr["result"] = 0;

            return json_encode($arr);
        }

        $arr["result"] = 1;

        if ($this->IsVideoInDrawer($VideoUID) == 0)
        {
            $sql = "insert into \"VideoDrawer\" (\"VideoUID\", \"UserUID\") values ('?video_Id?', '?my_Id?')";
            $sql = str_replace("?video_Id?", $VideoUID, $sql);
            $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

            $queryResult = $this->db->exesql($sql);
            if (pg_affected_rows($queryResult) == 0)
            {
                $arr["result"] = 0;
            }
        }

        return json_encode($arr);
    }

    function RemoveVideoFromDrawer()
    {
        $this->checkUser(true);

        $VideoUID = $this->getCleanValueFromArguments('VideoUID', true);

        $sql = "delete from \"VideoDrawer\" where \"VideoUID\"='?video_Id?' and \"UserUID\"='?my_Id?'";
        $sql = str_replace("?video_Id?", $VideoUID, $sql);
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);

        $queryResult = $this->db->exesql($sql);
        $arr["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;
        $arr["VideoUID"] = $VideoUID;

        return json_encode($arr);
    }

    function IncrementVideoUseCount()
    {
        $this->checkUser(true);

        $VideoUID = $this->getCleanValueFromArguments('VideoUID', true);

        $sql = "update \"Video\" set \"UseCount\"=\"UseCount\" + 1 where \"VideoUID\"='?video_Id?' returning \"UseCount\"";
        $sql = str_replace("?video_Id?", $VideoUID, $sql);
        $ret = $this->db->fetchValue($sql);

        $result["VideoUID"] = $VideoUID;
        if ($ret)
        {
            $result["UseCount"] = $ret;
            $result["result"] = 1;
        }
        else
        {
            $result["result"] = 0;
        }

        return json_encode($result);
    }

    function MakeVideosPublic()
    {
        $this->checkUser(true);

        $videoIDs = $this->getCleanValueFromArguments('VideoIDs', true);
        $videoArray = explode(',', $videoIDs);
        foreach ($videoArray as &$singleID)
        {
            $singleID = "'".$singleID."'";
        }
        unset($singleID);
        $videoIDs = implode(',', $videoArray);

        $sql = "update \"Video\" set \"IsPublic\"='true' where \"VideoUID\" in ($videoIDs) and \"OwnerUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $queryResult = $this->db->exesql($sql);

        $result["VideoIDs"] = $this->getCleanValueFromArguments('VideoIDs', true);
        $result["result"] = pg_affected_rows($queryResult) > 0 ? 1 : 0;

        return json_encode($result);
    }

    function GetItemsInDrawers()
    {
        $isUserLoggedIn = isset($this->arguments["email"]) || isset($this->arguments["username"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        #meshes
        if ($isUserLoggedIn)
        {
            $sql = "select \"MeshUID\" from \"MeshDrawer\" where \"UserUID\"='$this->currentUserId' and \"WasRemoved\" = false order by \"MeshDrawerUID\"";
        }
        else
        {
            $sql = "select \"MeshUID\" from \"Mesh\" where \"OwnerUID\"='$this->currentUserId' order by \"MeshUID\"";
        }
        $meshes = $this->db->exesqlAndReturnArray($sql);
        if ($meshes)
        {
            $arr["meshes"] = implode(',', $meshes);
        }

        if ($isUserLoggedIn)
        {
            $sql = "select \"MeshUID\" from \"MeshDrawer\" where \"UserUID\"='$this->currentUserId' and \"WasRemoved\" = true order by \"MeshDrawerUID\"";

            $removedMeshes = $this->db->exesqlAndReturnArray($sql);
            if ($removedMeshes)
                $arr["removedMeshes"] = implode(',', $removedMeshes);
        }

        
        #toy designer meshes
        if ($isUserLoggedIn)
        {
            $sql = "select \"MeshUID\" from \"MeshDrawerToyDesigner\" where \"UserUID\"='$this->currentUserId' order by \"MeshDrawerUID\"";
        }
        else
        {
            $sql = "select \"MeshUID\" from \"Mesh\" where \"OwnerUID\"='$this->currentUserId' and type=1 order by \"MeshUID\"";
        }
        $toyDesignerMeshes = $this->db->exesqlAndReturnArray($sql);
        if ($toyDesignerMeshes)
        {
            $arr["toyDesignerMeshes"] = implode(',', $toyDesignerMeshes);
        }

        #textures
        if ($isUserLoggedIn)
        {
            $sql = "select \"TextureUID\" from \"TextureDrawer\" where \"UserUID\"='$this->currentUserId' order by \"TextureDrawerUID\"";
        }
        else
        {
             $sql = "select \"TextureUID\" from \"Texture\" where \"OwnerUID\"='$this->currentUserId' order by \"TextureUID\"";
        }
        $textures = $this->db->exesqlAndReturnArray($sql);
        if ($textures)
        {
            $arr["textures"] = implode(',', $textures);
        }

        #videos
        if ($isUserLoggedIn)
        {
            $sql = "select \"VideoUID\" from \"VideoDrawer\" where \"UserUID\"='$this->currentUserId' order by \"VideoDrawerUID\"";
        }
        else
        {
            $sql = "select \"VideoUID\" from \"Video\" where \"OwnerUID\"='$this->currentUserId' order by \"VideoUID\"";
        }
        $videos = $this->db->exesqlAndReturnArray($sql);
        if ($videos)
        {
            $arr["videos"] = implode(',', $videos);
        }

 //       #mesh templates
 //       if ($isUserLoggedIn)
 //       {
 //           $sql = "select \"MeshUID\" from \"MeshTemplates\" where \"UserUID\"='$this->currentUserId' order by \"MeshTemplateUID\"";
 //           $meshTemplates = $this->db->exesqlAndReturnArray($sql);
 //           $arr["meshTemplates"] = $meshTemplates ? implode(',', $meshTemplates) : "";
 //       }
 //       else
 //       {
 //           $arr["meshTemplates"] = $arr["meshes"];
 //       }

		#groups
        if ($isUserLoggedIn)
        {
            $sql = "select \"GroupUID\" from \"GroupDrawer\" where \"UserUID\"='$this->currentUserId' order by \"GroupDrawerUID\"";
        }
        else
        {
            $sql = "select \"GroupUID\" from \"Group\" where \"UserUID\"='$this->currentUserId' order by \"GroupUID\"";
        }
        $groups = $this->db->exesqlAndReturnArray($sql);
        if ($groups)
        {
            $arr["groups"] = implode(',', $groups);
        }


        #group templates
        if ($isUserLoggedIn)
        {
            $sql = "select \"GroupUID\" from \"GroupTemplates\" where \"UserUID\"='$this->currentUserId' order by \"GroupTemplateUID\"";
            $groupTemplates = $this->db->exesqlAndReturnArray($sql);
            if ($groupTemplates)
            {
                $arr["groupTemplates"] = implode(',', $groupTemplates);
            }
        }
        else if ($groups)
        {
            $arr["groupTemplates"] = $arr["groups"];
        }

        #swatches
        $sql = "select * from \"Swatches\" where \"UserUID\"='$this->currentUserId' order by \"SwatchUID\"";
        $swatches = $this->db->sqlToArray($sql);
        if ($swatches)
        {
            for ($i=0; $i < count($swatches); $i++)
            {
                $swatches[$i]['Color'] = (int)$swatches[$i]['Color'];
                $swatches[$i]['Color2'] = (int)$swatches[$i]['Color2'];
                $swatches[$i]['Gradient'] = (int)$swatches[$i]['Gradient'];
                $swatches[$i]['TexGradient'] = (int)$swatches[$i]['TexGradient'];
                $swatches[$i]['OutlineColor'] = (int)$swatches[$i]['OutlineColor'];
            }
    
            $arr["swatches"] = $swatches;
        }

        $arr["result"] = 1;

        return json_encode($arr);
    }

    function ChangeItemsOwner()
    {
        $this->checkUser(true);

        $sql = "select \"SessionToken\" from \"User\" where \"UserUID\"='?my_Id?'";
        $sql = str_replace("?my_Id?", $this->currentUserId, $sql);
        $result = $this->db->fetchArray($sql);
        $sessionToken = $result['SessionToken'];

        $previousUserID = $this->getCleanValueFromArguments("previousUserID", true);
        $sql = "select \"Password\" from \"User\" where \"UserUID\"='?user_Id?'";
        $sql = str_replace("?user_Id?", $previousUserID, $sql);
        $result = $this->db->fetchArray($sql);
        if (!$result)
        {
            die($this->JsonError('Previous user cannot be found.', 'ServerMessage50'));
        }
        $previousUserPassword = $result['Password'];

        $expectedHash = $this->getCleanValueFromArguments("previousUserPassword", true);
        $hash = md5($previousUserPassword.$sessionToken);

        if ($hash !== $expectedHash)
        {
            die($this->JsonError('Previous user password does not match.', 'ServerMessage51'));
        }
        else
        {
            $affected_rows = 0;

            $queryResult = $this->db->exesql("update \"Design\" set \"OwnerUID\"='$this->currentUserId' where \"OwnerUID\"='$previousUserID'");
            $affected_rows = $affected_rows + pg_affected_rows($queryResult);
            $queryResult = $this->db->exesql("update \"Mesh\" set \"OwnerUID\"='$this->currentUserId' where \"OwnerUID\"='$previousUserID'");
            $affected_rows = $affected_rows + pg_affected_rows($queryResult);
            $queryResult = $this->db->exesql("update \"Group\" set \"UserUID\"='$this->currentUserId' where \"UserUID\"='$previousUserID'");
            $affected_rows = $affected_rows + pg_affected_rows($queryResult);
            $queryResult = $this->db->exesql("update \"Texture\" set \"OwnerUID\"='$this->currentUserId' where \"OwnerUID\"='$previousUserID'");
            $affected_rows = $affected_rows + pg_affected_rows($queryResult);
            $queryResult = $this->db->exesql("update \"Video\" set \"OwnerUID\"='$this->currentUserId' where \"OwnerUID\"='$previousUserID'");
            $affected_rows = $affected_rows + pg_affected_rows($queryResult);

            if ($affected_rows > 0)
            {
                #reset previous user's items in drawers
                $this->db->exesql("delete from \"TextureDrawer\" where \"UserUID\"='$previousUserID'");
                $this->db->exesql("delete from \"VideoDrawer\" where \"UserUID\"='$previousUserID'");
                $this->db->exesql("delete from \"MeshDrawer\" where \"UserUID\"='$previousUserID'");
                $this->db->exesql("delete from \"MeshDrawerToyDesigner\" where \"UserUID\"='$previousUserID'");
                //$this->db->exesql("delete from \"MeshTemplates\" where \"UserUID\"='$previousUserID'");
                $this->db->exesql("delete from \"GroupDrawer\" where \"UserUID\"='$previousUserID'");
                $this->db->exesql("delete from \"GroupTemplates\" where \"UserUID\"='$previousUserID'");
                $this->db->exesql("delete from \"Swatches\" where \"UserUID\"='$previousUserID'");
                $this->SetUserDefaultSettings($previousUserID);
            }

            $arr["itemsUpdated"] = $affected_rows;
            $arr["result"] = 1;
            return json_encode($arr);
        }
    }

    function SharePicture()
    {
        $fileHandler = new FileHandler();
        $result = $fileHandler->saveFilesToUserDir("/var/www/html/picto/img/share/");
        $result['filename'] = $_SESSION['fileNames'];
        return json_encode($result);
    }

    function SendQuestion()
    {
        $isUserLoggedIn = isset($this->arguments["token"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $questionType = $this->getCleanValueFromArguments('type', true);
        $questionMessage = "Message:<br/>" . $this->getCleanValueFromArguments('message', true);

        $this->arguments['to'] = $this->support_email_address;
        if ($questionType == 1)
        {
            // editor general question
            $this->arguments['subject'] = "General help";
        }
        else if ($questionType == 2)
        {
            // buy options question
            $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
            $this->arguments['subject'] = "Buy options help";
            $questionMessage = "Design ID: " . $DesignUID . "<br/>" . $questionMessage;
        }

        if ($isUserLoggedIn)
        {
            $displayName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\"='$this->currentUserId'");
            $questionMessage = "Sender name: " . $displayName . "<br/>Sender ID: " . $this->currentUserId . "<br/>" . $questionMessage;
        }
        else
        {
            $questionMessage = "Sender email: " . $this->getCleanValueFromArguments('email', true) . "<br/>" . $questionMessage;
        }
        $this->arguments['message'] = $questionMessage;

        $this->SendEmail($isUserLoggedIn, true);

        $arr["result"] = 1;

        return json_encode($arr);
    }

    function SendNotification()
    {
        $isUserLoggedIn = isset($this->arguments["token"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $notificationSubject = $this->getCleanValueFromArguments('subject', true);
        $notificationMessage = "Message:<br/>" . $this->getCleanValueFromArguments('message', true);

        $this->arguments['to'] = $this->support_email_address;

        if ($isUserLoggedIn)
        {
            $displayName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\"='$this->currentUserId'");
            $notificationMessage = "Application: " . $this->application_name . "<br/>User name: " . $displayName . "<br/>User ID: " . $this->currentUserId . "<br/>" . $notificationMessage;
        }
        else
        {
            $notificationMessage = "Application: " . $this->application_name . "<br/>User not logged in<br/>" . $notificationMessage;
        }
        $this->arguments['message'] = $notificationMessage;
        $this->arguments['email'] = $this->support_email_address;

        $this->SendEmail($isUserLoggedIn, true);

        $arr["result"] = 1;

        return json_encode($arr);
    }

    function ReportAbuse()
    {
        $isUserLoggedIn = isset($this->arguments["token"]);

        if ($isUserLoggedIn)
        {
            $this->checkUser(true);
        }

        $DesignUID = $this->getCleanValueFromArguments('DesignUID', true);
        $reportType = $this->getCleanValueFromArguments('type', true);
        $reportMessage = "Message:<br/>" . $this->getCleanValueFromArguments('message', true);

        $this->arguments['to'] = $this->support_email_address;
        if ($reportType == 1)
        {
            // reporting design
            $this->arguments['subject'] = "Report design abuse";
        }
        else if ($reportType == 2)
        {
            // reporting comment
            $CommentUID = $this->getCleanValueFromArguments('CommentUID', true);
            $this->arguments['subject'] = "Report comment abuse";
            $reportMessage = "Comment ID: " . $CommentUID . "<br/>" . $reportMessage;
        }
        else if ($reportType == 3)
        {
            // reporting mesh, group, texture or video
            $assetType = (int)$this->getCleanValueFromArguments('AssetType', true);
            $assetUID = $this->getCleanValueFromArguments('AssetUID', true);
            if ($assetType == 0) // mesh
            {
                $this->arguments['subject'] = "Report shape abuse";
                $reportMessage = "Shape ID: " . $assetUID . "<br/>" . $reportMessage;
            }
            else if ($assetType == 1) // group
            {
                $this->arguments['subject'] = "Report group abuse";
                $reportMessage = "Group ID: " . $assetUID . "<br/>" . $reportMessage;
            }
            else if ($assetType == 2) // texture
            {
                $this->arguments['subject'] = "Report pattern abuse";
                $reportMessage = "Pattern ID: " . $assetUID . "<br/>" . $reportMessage;
            }
            else //if ($assetType == 3) // video
            {
                $this->arguments['subject'] = "Report video abuse";
                $reportMessage = "Video ID: " . $assetUID . "<br/>" . $reportMessage;
            }
        }

        if ($isUserLoggedIn)
        {
            $displayName = $this->db->fetchValue("select \"UserName\" from \"User\" where \"UserUID\"='$this->currentUserId'");
            $reportMessage = "Sender name: " . $displayName . "<br/>Sender ID: " . $this->currentUserId . "<br/>Design ID: " . $DesignUID . "<br/>" . $reportMessage;
        }
        else
        {
            $reportMessage = "Sender email: " . $this->getCleanValueFromArguments('email', true) . "<br/>Design ID: " . $DesignUID . "<br/>" . $reportMessage;
        }
        $this->arguments['message'] = $reportMessage;

        $this->SendEmail($isUserLoggedIn, true);

        $arr["result"] = 1;

        return json_encode($arr);
    }

    function ClearTables()
    {
        $this->checkUser(true);

        if ($this->currentUserId == 25 || $this->currentUserId == 13)
        {
            $clearTags = $this->getCleanValueFromArguments('clearTags');
            if ($clearTags == 1)
            {
                $this->db->exesql('delete from "DesignTag"');
            }
            $clearDesigns = $this->getCleanValueFromArguments('clearDesigns');
            if ($clearDesigns == 1)
            {
                $this->db->exesql('delete from "Design"');
            }
            $clearMeshes = $this->getCleanValueFromArguments('clearMeshes');
            if ($clearMeshes == 1)
            {
                $this->db->exesql('delete from "Mesh"');
            }
            $clearTextures = $this->getCleanValueFromArguments('clearTextures');
            if ($clearTextures == 1)
            {
                $this->db->exesql('delete from "Texture"');
            }
            $clearLikes = $this->getCleanValueFromArguments('clearLikes');
            if ($clearLikes == 1)
            {
                $this->db->exesql('delete from "Like"');
            }
            $clearFavorites = $this->getCleanValueFromArguments('clearFavorites');
            if ($clearFavorites == 1)
            {
                $this->db->exesql('delete from "Favorite"');
            }
            $clearComments = $this->getCleanValueFromArguments('clearComments');
            if ($clearComments == 1)
            {
                $this->db->exesql('delete from "Comments"');
            }
        }

        $arr["result"] = 1;
        return json_encode($arr);
    }

    function ModifyDatabase()
    {
        $this->checkUser(true);

        $arr["result"] = 0;

        $this->GenerateMissingThumbnails();

        //$query = $this->getCleanValueFromArguments('query');
        //if ($query != '' && ($this->currentUserId == 25 || $this->currentUserId == 13))
        //{
        //    $arr["result"] = $this->db->exesql($query) ? 1 : 0;
        //}

        return json_encode($arr);
    }


    private function getValidMethodList()
    {
        return array('AddNotificationDeviceToken', 'SetUserInfo', 'GetUserInfo', 'SendForgetPasswordLink', 'ResetPassword', 'CreateAccount', 'CreateAccountWithUsername', 'ActivateAccount', 'LogoutUser', 'SchoologyAuthPreLogin', 'SchoologyAuthPostLogin', 'LoginWithSchoology', 'SchoologyCreateAccount',
                    'FollowUser', 'UnfollowUser', 'ChangePassword', 'ResetUserSettings', 'LoginOrCreateUser', 'ChangeItemsOwner', 'SetExportFlag', 'SetSchoolPolicyFlags', 'SetClassPolicyFlags', 'GetPolicyFlags',
                    'VerifyCode', 'SetCategory', 'LoginOrCreateUserWithUsername', 'GetUserName',
                    'AddLevel', 'EditLevel', 'UpdateLevelData', 'DeleteLevel', 'GetMissingOrOutdatedLevels', 'GetOwnedLevels', 'GetFeaturedLevels', 'EditTags', 'AddOrRemoveTags',
                    'GetMatchingLevels', 'GetMissingOwnedDesigns', 'FavoriteDesign', 'UnfavoriteDesign', 'LikeDesign', 'UnlikeDesign', 'IncrementViewCount', 'GetDesignData', 'UpdateModelColors',
                    'ShareDesign', 'SharePicture', 'AddComment', 'UpdateComment', 'DeleteComment', 'GetComments', 'RateComment', 'GetPopularTags', 'AddDesignPhoto', 'RemoveDesignPhoto', 'ApproveDesignPhoto', 'RejectDesignPhoto', 'GetMoreDesignPhotos',// 'AcceptDesignPhoto',
                    'AddTexture', 'EditTexture', 'SetTextureThumbnail', 'GetOwnedTextures', 'AddTextureTags',
                    'GetMissingTextures', 'IncrementTextureUseCount', 'MakeTexturesPublic', 'AddTextureToDrawer', 'RemoveTextureFromDrawer', 'GetMatchingTextures',
                    'AddVideo', 'GetOwnedVideos', 'GetMissingVideos', 'IncrementVideoUseCount', 'MakeVideosPublic', 'AddVideoToDrawer', 'RemoveVideoFromDrawer',
                    'GetMatchingVideos', //'EditVideo', 'AddVideoTags',
                    'AddMesh', 'EditMesh', 'DeleteMeshByName', 'GetOwnedMeshes', 'GetMissingMeshes', 'IncrementMeshUseCount', 'MakeMeshesPublic', 'AddMeshToDrawer', 'RemoveMeshFromDrawer',
                    'GetMatchingMeshes', 'AddMeshTags', 'GetMeshData', 'UpdateSwatch', 'GetItemsInDrawers', 'AddOrRemoveMeshTags', //'ReplaceMeshTemplate',
                    'AddGroup', 'EditGroup', 'DeleteGroup', 'GetOwnedGroups', 'MakeGroupsPublic', 'AddGroupToDrawer', 'RemoveGroupFromDrawer', 'GetMatchingGroups',
                    'IncrementGroupUseCount', 'GetMissingGroups', 'ReplaceGroupTemplate', 'AddGroupTags',
                    'CreatePurchaseItem', 'GetBuyOptions',
                    'PreviewDesign', 'GetDesignsToRender', 'AddDesignToRender', 'RefreshRenderRequest', 'SetDesignCover', 'GetDesignsToExport', 'ExportDesignToSTL', 'OrderPrintOfDesign', 'PrioritiseDesignExport', 
                    'RefreshExportRequest', 'SendExportedDesign',

                    'SubmitDesignToCompetition', 'GetCompetitionEntries', 'GetDesignCompetitionStatus', 'FetchCompetitionEntryDescription',
                    'GetUserNotifications', 'NotificationShownToUser', 'CloseInAppNotification',

                    'DailyProcess',

                    'NewUser', 'LoginUser', 'SaveResultData', 'GetResultData', 'SetHighLevel',

                    'SendQuestion', 'ReportAbuse', 'SendNotification',

                    'GetMaterialsForDesign', 'GetDeliveryPrice',
                    'SetMakerBotCode',
                    'AddTrigger', 'SetTriggerImage',
                    'ClearTables', 'ModifyDatabase', 'DeleteTexture', 'DeleteVideo' // TODO: remove this later
                    , 'AddAllToRenderQueue','CheckImageCreatorIdleTime','AddAllToExportQueue'
                    
                    , 'CreateUnlockCodes', 'SetVariousUserDefaults', 'ClearImagesFromDeletedDesigns', 'ClearStlsFromDeletedDesigns', 'DeleteMEThings'
                    );
    }
}
?>
