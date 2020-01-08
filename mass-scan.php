<?php
/**
* @author Nando aka GreyCat
* @since 2020
* USAGE : 

php mass-scan.php --scan=<list dir to scan OR put dirname to specify dir scan> --output=<output file name> --show-files=< 0 = only show amount of threats,1 = show files threat only, 2 = show all files scanned

*/
    set_time_limit(999999);

    class BackdoorScanner{
        private $backdoorStrings = [
            "passthru.*.\\\$_(GET|POST)", "exec.*.\\\$_(GET|POST)",
            "shell_exec.*.\\\$_(GET|POST)", "system.*.\\\$_(GET|POST)",
            "extract.*.\\\$_(GET|POST)", "extract.*.\\\$_REQUEST", "edoced_46esab",
            "HTTP_USER_AGENT",

            // SPECIFIC CASE //
            /* base64_decode may be false positive => */ 
            /* dynamic functions may be false positive => */ "\\\$\\w+\\s*\\(",
            // scanning results on vendor folder or any CMS may be MUCH FALSE POSITIVE

            // Add more backdoor strings below (Support REGEX)
            "indoxploit", "galerz", "backdoor", "php-cgi-shell", "cgi-shell",
            "php shell", "deface", "symlink", "adminer", "zone-h" , "zoneh", "defacer.id",
            "defacer id", "brute force","move_uploaded_file","copy","kudusxploit","kudusXploit"
        ];

        private $exactlyMatches = 5; // aggressive level (less is more aggressive)

        public  $exactlyNum = 1;
        private $scanResults;
        private $exactlyPattern;
        private $excludes = ['libraries','vendor','/system','PHPExcel','psa-webmail'];

        public function scanDirs($showFiles,$output,$dir, $results = array())
        {
            $colors = new Colors();
            $files  = scandir($dir);
            
            foreach($files as $file)
            {
                $path       = realpath($dir . DIRECTORY_SEPARATOR . $file);
                $extension  = pathinfo($path, PATHINFO_EXTENSION);

                if(!is_dir($path))
                {
                    if($extension == "php" && $path != __FILE__)
                    {
                        $backdoorPattern = "@(" . implode("|",$this->backdoorStrings) . ")@i";
                        $exactlyPattern = "@(htaccess|system.*.\\(|phpinfo.*.\\(|base64_decode.*.\\(|chmod|create_function|mkdir|fopen.*.\\(|readfile.*.\\(|(eval|passthru|shell_exec|exec))@i";

                        $fileContent = file_get_contents($path);
                        
                        if (!$this->contains($path,$this->excludes)) 
                        {
                            if(preg_match($backdoorPattern, $fileContent))
                            {
                                if ($showFiles == 1 || $showFiles == 2) 
                                {
                                    echo $colors->getColoredString($path."-> threat backdoor (possible false positive)\n","red");
                                }

                                if (!empty($output)) 
                                {
                                   file_put_contents($output, $path.PHP_EOL , FILE_APPEND | LOCK_EX);
                                }

                                $this->exactlyNum++;
                                continue;

                                if(preg_match_all($exactlyPattern,$fileContent,$matches))
                                {
                                    foreach($matches[0] as $match){
                                        $this->exactlyPattern[$match] = 1;
                                    }
                                    $totalPattern = count($this->exactlyPattern);
                                    $this->exactlyPattern = [];
                                    if($totalPattern >= $this->exactlyMatches){
                                        $this->exactlyNum++;
                                    }
                                }
                            }
                            else
                            {
                                if ($showFiles == 2) 
                                {
                                    echo $this->exactlyNum.'-'.$path."-> aman \n";
                                }
                            }
                        }
                    }
                    $this->exactlyNum++;
                }
                else if($file != "." && $file != "..")
                {
                    $results = $this->scanDirs($showFiles,$output,$path, $results);
                }
            }
        }

        public function contains($str, array $arr)
        {
            foreach($arr as $a) {
                if (stripos($str,$a) !== false) return true;
            }
            return false;
        }
    }


    class Colors {
        private $foreground_colors = array();
        private $background_colors = array();

        public function __construct() {
            // Set up shell colors
            $this->foreground_colors['black'] = '0;30';
            $this->foreground_colors['dark_gray'] = '1;30';
            $this->foreground_colors['blue'] = '0;34';
            $this->foreground_colors['light_blue'] = '1;34';
            $this->foreground_colors['green'] = '0;32';
            $this->foreground_colors['light_green'] = '1;32';
            $this->foreground_colors['cyan'] = '0;36';
            $this->foreground_colors['light_cyan'] = '1;36';
            $this->foreground_colors['red'] = '0;31';
            $this->foreground_colors['light_red'] = '1;31';
            $this->foreground_colors['purple'] = '0;35';
            $this->foreground_colors['light_purple'] = '1;35';
            $this->foreground_colors['brown'] = '0;33';
            $this->foreground_colors['yellow'] = '1;33';
            $this->foreground_colors['light_gray'] = '0;37';
            $this->foreground_colors['white'] = '1;37';

            $this->background_colors['black'] = '40';
            $this->background_colors['red'] = '41';
            $this->background_colors['green'] = '42';
            $this->background_colors['yellow'] = '43';
            $this->background_colors['blue'] = '44';
            $this->background_colors['magenta'] = '45';
            $this->background_colors['cyan'] = '46';
            $this->background_colors['light_gray'] = '47';
        }

        // Returns colored string
        public function getColoredString($string, $foreground_color = null, $background_color = null) {
            $colored_string = "";

            // Check if given foreground color found
            if (isset($this->foreground_colors[$foreground_color])) {
                $colored_string .= "\033[" . $this->foreground_colors[$foreground_color] . "m";
            }
            // Check if given background color found
            if (isset($this->background_colors[$background_color])) {
                $colored_string .= "\033[" . $this->background_colors[$background_color] . "m";
            }

            // Add string and end coloring
            $colored_string .=  $string . "\033[0m";

            return $colored_string;
        }

        // Returns all foreground color names
        public function getForegroundColors() {
            return array_keys($this->foreground_colors);
        }

        // Returns all background color names
        public function getBackgroundColors() {
            return array_keys($this->background_colors);
        }
    }

?>


<?php
    $arg1 = @$argv[1];
    if (!strstr($arg1,"--scan")) 
    {
        die('Fill --scan correctly !');
    }

    $scan = trim(explode("=", $arg1)[1]);
    $path = $scan;

    if (!is_file($scan) && !strstr($scan,'/')) 
    {
        die($scan." not found!\n");
    }

    if (is_file($scan)) 
    {
        $path   = file($scan);
    }

    $arg2 = @$argv[2];
    if (!strstr($arg2,"--output")) 
    {
        die('Fill --output correctly !');
    }

    $output = trim(explode("=", $arg2)[1]);
    
    $arg3 = @$argv[3];
    if (!strstr($arg3,"--show-files")) 
    {
        die('Fill --show-files correctly !');
    }
    
    $showFiles = trim(explode("=", $arg3)[1]);

    $colors = new Colors();
    $no = 1;

    echo "  ____  ____  ____                                  
 | __ )|  _ \/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
 |  _ \| | | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |_) | |_| |___) | (_| (_| | | | | | | |  __/ |   
 |____/|____/|____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                    @author : GreyCat - cR0ot\n\n";
    if (is_file($scan)) 
    {
        foreach ($path as $key => $path) 
        {
            $path = trim($path);
            $nl = "";
            if ($showFiles == 1) 
            {
                $nl = "\n";
            }

            echo $no.". ".$colors->getColoredString($path,'yellow').$nl;
            $scanner = new BackdoorScanner();
            $x = $scanner->scanDirs($showFiles,$output,$path);

            if ($showFiles == 0) 
            {
                $f = file_get_contents($output);
                echo " - Threats found : ".substr_count($f,$path)."\n\n";
            }

            $no++;
        }
    }
    else
    {
        $nl = "";
        if ($showFiles == 1) 
        {
            $nl = "\n";
        }

        echo $no.". ".$colors->getColoredString($path,'yellow').$nl;
        $scanner = new BackdoorScanner();
        $x = $scanner->scanDirs($showFiles,$output,$path);

        if ($showFiles == 0) 
        {
            $f = file_get_contents($output);
            echo " - Threats found : ".substr_count($f,$path)."\n\n";
        }

        $no++;
    }
?>

