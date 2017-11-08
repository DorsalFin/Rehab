 <?php
require_once 'config.php';
require_once 'pgConnect.php';
require_once 'FileHandler.php';
require_once 'vuforia/vuforia.php';

require 'vendor/autoload.php';
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

class API
{
    public $arguments;
    public $db;


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

                        if ($gameName == "pop_pop") 
                            continue;

                        if ($gameName == "basketball")
                            $sql = "select array_upper(action_times, 1) as actions from results where user_id = $userId and game = '$gameName' and difficulty = $i and array_upper(action_times, 1) > 0 order by actions desc limit 1";
                        else
                            $sql = "select end_time - start_time as time from results where user_id = $userId and game = '$gameName' and difficulty = $i and win = true order by start_time - end_time desc limit 1";

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
            
            $sql = "select * from results where user_id = $user_id and game = '$game' and record = true";
            $recordResults = $this->db->sqlToArray($sql);
            if ($recordResults)// && count($recordResults) > 3)
                $arr["recordResults"] = $recordResults;
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

    private function getValidMethodList()
    {
        return array('NewUser', 'LoginUser', 'SaveResultData', 'GetResultData', 'SetHighLevel');
    }
}
?>
