
<?php
error_reporting(0);


class waf{
    
    private $request_url;
    private $request_method;
    private $request_data;
    private $headers;
    private $raw;
    /*
    waf类
    */

    
// 自动部署构造方法
function __construct(){
    if($_SERVER['REQUEST_METHOD'] != 'POST' && $_SERVER['REQUEST_METHOD'] != 'GET'){
    write_attack_log("method");
    }
    //echo "class waf construct execute..3</br>";
    $this->request_url= $_SERVER['REQUEST_URI']; //获取url来进行检测


    $this->request_data = file_get_contents('php://input'); //获取post

    $this->headers =$this->get_all_headers(); //获取header  

    //echo "class waf construct execute half..</br>";


    $this->filter_attack_keyword($this->filter_invisible(urldecode($this->filter_0x25($this->request_url)))); //对URL进行检测，出现问题则拦截并记录
    $this->filter_attack_keyword($this->filter_invisible(urldecode($this->filter_0x25($this->request_data)))); //对POST的内容进行检测，出现问题拦截并记录
    //echo "class waf construct execute..4</br>";
    $this->detect_upload();

    $this->gloabel_attack_detect();
    
    
    //echo "class waf construct execute  success..</br>";



}

//全局输入检测  基本的url和post检测过了则对所有输入进行简单过滤

function gloabel_attack_detect(){
    
    foreach ($_GET as $key => $value) {
        $_GET[$key] = $this->filter_dangerous_words($value);
    }
    foreach ($_POST as $key => $value) {
        $_POST[$key] = $this->filter_dangerous_words($value);
    }
    foreach ($headers as $key => $value) {
        $this->filter_attack_keyword($this->filter_invisible(urldecode(filter_0x25($value)))); //对http请求头进行检测，出现问题拦截并记录
        $_SERVER[$key] = $this->filter_dangerous_words($value); //简单过滤
    }
}


//拦截所有的文件上传  并记录上传操作  并将上传文件保存至系统tmp文件夹下
function detect_upload(){
    foreach ($_FILES as $key => $value) {
        if($_FILES[$key]['size']>1){
            echo "upload file error";
            $this->write_attack_log("Upload");
            //move_uploaded_file($_FILES[$key]["tmp_name"],'/tmp/uoloadfiles/'.$_FILES[$key]["name"]);
            exit(0);
        }
    }
}
    
    
/*
获取http请求头并写入数组
*/
function get_all_headers() { 
    $headers = array(); 
 
    foreach($_SERVER as $key => $value) { 
        if(substr($key, 0, 5) === 'HTTP_') { 
            $headers[$key] = $value; 
        } 
    } 
 
    return $headers; 
}
/*
检测不可见字符造成的截断和绕过效果，注意网站请求带中文需要简单修改
*/
function filter_invisible($str){
    for($i=0;$i<strlen($str);$i++){
        $ascii = ord($str[$i]);
        if($ascii>126 || $ascii < 32){ //有中文这里要修改
            if(!in_array($ascii, array(9,10,13))){
                write_attack_log("interrupt");
            }else{
                $str = str_replace($ascii, " ", $str);
            }
        }
    }
    $str = str_replace(array("`","|",";",","), " ", $str);
    return $str;
}

/*
检测网站程序存在二次编码绕过漏洞造成的%25绕过，此处是循环将%25替换成%，直至不存在%25
*/
function filter_0x25($str){
    if(strpos($str,"%25") !== false){
        $str = str_replace("%25", "%", $str);
        return filter_0x25($str);
    }else{
        return $str;
    }
}   


/*
攻击关键字检测，此处由于之前将特殊字符替换成空格，即使存在绕过特性也绕不过正则的\b
*/
function filter_attack_keyword($str){
    if(preg_match("/select\b|insert\b|update\b|drop\b|and\b|delete\b|dumpfile\b|outfile\b|load_file|rename\b|floor\(|extractvalue|updatexml|name_const|multipoint\(|substr\(|ascii\(|if\(|information|schema|\'|\"/i", $str)){
        $this->write_attack_log("sqli");
    }

    //文件包含的检测
    if(substr_count($str,$_SERVER['PHP_SELF']) < 2){
        $tmp = str_replace($_SERVER['PHP_SELF'], "", $str);
        if(preg_match("/\.\.|.*\.php[35]{0,1}/i", $tmp)){ 
            $this->write_attack_log("LFI/LFR");;
        }
    }else{
        $this->write_attack_log("LFI/LFR");
    }
    if(preg_match("/base64_decode|eval\(|assert\(|file_put_contents|fwrite|curl|system|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restorei|init|reboot|cat|var_dump|ls|type|echo|shutdown|poweroff|halt|msht|control|notepad|calc|services.msc|lusrmgr.msc|\^|rm|-|rf|find|head|less|more|tac|od|nl|tail|vi|ps/i", $str)){
        $this->write_attack_log("EXEC");
    }
    if(preg_match("/flag/txt/i", $str)){
        $this->write_attack_log("GETFLAG");
    }
    if(preg_match("/php:|file|php:\/\/filter|data:\/\/|zip:\/\/|glob/i", $str)){
      
    	  $this->write_attack_log("GETFLAG");
    }

}

/*
简单将易出现问题的字符替换成中文
*/
function filter_dangerous_words($str){
    $str = str_replace("'", "‘", $str);
    $str = str_replace("\"", "“", $str);
    $str = str_replace("<", "《", $str);
    $str = str_replace(">", "》", $str);
    $str = str_replace("*","星号",$str);
    $str = str_replace("^"," ",$str);
    $str = str_replace("\\","、",$str);
    $str = str_replace("(","（",$str);
    $str = str_replace(")","（",$str);
    $str = str_replace("\$","￥",$str);
    $str = str_replace("^","……",$str);
    $str = str_replace("+","加号",$str);
    $str = str_replace("#","注释？？？",$str);
    $str = str_replace("&","与",$str);
    $str = str_replace("%","百分号",$str);
    echo $str;
    return $str;
}

/*
获取http的请求包，意义在于获取别人的攻击payload
*/
function get_http_raws() { 
    $raw = ''; 

    $raw .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n"; 
     
    foreach($_SERVER as $key => $value) { 
        if(substr($key, 0, 5) === 'HTTP_') { 
            $key = substr($key, 5); 
            $key = str_replace('_', '-', $key); 
            $raw .= $key.': '.$value."\r\n"; 
        } 
    } 
    $raw .= "\r\n"; 
    $raw .= file_get_contents('php://input'); 
    return $raw; 
}
           
/*
这里拦截并记录攻击payload      第一个参数为记录类型   第二个参数是日志内容   使用时直接调用函数
*/
function write_attack_log($alert){
    if($alert == 'GETFLAG'){
        echo "CTF{H4Ck_IS_s0_c001}"; //如果请求带有flag关键字，显示假的flag。（2333333）
    }else{
        sleep(3); //拦截前延时3秒
    }
    exit(0);
}

    
}
$waf = new waf();

?>

<?php

$time=date('m_d_H_').(int)(date('i')/10);
$remote_ip = $_SERVER['REMOTE_ADDR'];

/* 
    mode 1: record malicious payload, but do nothing;
    mode 2: record malicious payload, and handle with the malicious payloads;
    mode 3: record malicious payload, and using IP waf to handle malicious payloads;
    mode 4: record malicious payload, and using proxy
    mode 5: using IP waf to stop everything
*/

define('WAF_MODE',1);

define('WAF_PATH','/var/www/html/my_waf/');
define('LOG_PATH','/var/www/html/my_waf/log/');
define('LOG_ALL_PATH','/var/www/html/my_waf/log_all/');
define('LOG_FILENAME',LOG_PATH."cap-".$remote_ip."-".$time.'.txt');
define('LOG_ALL_FILENAME',LOG_ALL_PATH."allcap-".$remote_ip."-".$time.'.txt');
define('LOG_HTTP',true);
define('LOG_ARGS',false);
define('ALL_RECORD',true);
define('DEBUG',false);
define('REWRITE_UPLOAD',true);
define('MALICIOUS_DIE',false);
define('MALICIOUS_UNSET',true);
define('PROXY_HOST','172.17.0.2');
define('PROXY_PORT',80);
$white_ip_list = array();
$black_ip_list = array('172.17.0.1');

// config ends

if(DEBUG){
    error_reporting(E_ERROR | E_WARNING | E_PARSE);
}

function debug_echo($msg){
    if(DEBUG){
        echo $msg;
    }
}

function debug_var_dump($msg){
    if(DEBUG){
        var_dump($msg);
    }
}

function waf(){
    if (!function_exists('getallheaders')) {
        function getallheaders() {
            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_')
                    $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
            return $headers;
        }
    }
    $get = $_GET;
    $post = $_POST;
    $cookie = $_COOKIE;
    $header = getallheaders();
    $files = $_FILES;
    $ip = $_SERVER["REMOTE_ADDR"];
    $method = $_SERVER['REQUEST_METHOD'];
    $filepath = $_SERVER["SCRIPT_NAME"];

    //if REWRITE_UPLOAD is set, rewirte shell which uploaded by others
    if(REWRITE_UPLOAD){
        foreach ($_FILES as $key => $value) {
            $files[$key]['content'] = file_get_contents($_FILES[$key]['tmp_name']);
            file_put_contents($_FILES[$key]['tmp_name'], "virink");
        }
    }

    unset($header['Accept']);//fix a bug
    $input = array("Get"=>$get, "Post"=>$post, "Cookie"=>$cookie, "File"=>$files, "Header"=>$header);
    // the filter rules
    $pattern = "select|insert|update|delete|union|load_file|outfile|dumpfile|sub|hex";
    $pattern .= "|file_put_contents|fwrite|curl|system|eval|assert|flag";
    $pattern .="|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore";
    $pattern .="|`|openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|assert|pcntl_exec";
    $vpattern = explode("|",$pattern);
    $bool = false;

    //if ALL_RECORD banner is set, then all the traffic is going to be recorded
    if(ALL_RECORD){
       logging($input,LOG_ALL_FILENAME);
    }

    //judge whether a data flow is malicious
    foreach ($input as $k => $v) {
        foreach($vpattern as $value){
            foreach ($v as $kk => $vv) {
                if (preg_match( "/$value/i", $vv )){
                    $bool = true;
                    if(DEBUG){
                        var_dump($value);
                        var_dump($vv);
                    }
                    logging($input,LOG_FILENAME);
                    //malicious data flow
                    return True;
                }
            }
        }
    }
    //normal data flow
    return False;
}


function logging($var,$filename)
{
    /*
    this function is used to record the traffic received by the WAF
    */

    //if LOG_ARGS is set, writing the log with the var_dump format
    if(LOG_ARGS){
        file_put_contents($filename, "\n".date("m-d H:i:s")."  ".$_SERVER['REMOTE_ADDR']."\n".print_r($var, true), FILE_APPEND);
    }

    //if LOG_HTTP is set, writing the log with the format of the basic http request
    if(LOG_HTTP){
        $http_log = "\n".$_SERVER['REQUEST_METHOD']." ".$_SERVER['REQUEST_URI']." HTTP/1.1\n";
        foreach(getallheaders() as $key => $value){
            $http_log .=   $key.": ".$value."\n";
        }
        $is_first = true;
        $http_log .= "\n";
        foreach($_POST as $key => $value){
            if(!$is_first){ $http_log .= '&';}
            $http_log .= $key."=".$value;
            $is_first = false;
        }
        file_put_contents($filename, $http_log,  FILE_APPEND);
    }
}

function handle_malicious($msg='I am waf;go die'){
    /*
    this function is used to handle with situation where the malicious payloads are found
    */

    //if MALICIOUS_UNSET is set, unset all the super global variables
    if(MALICIOUS_UNSET){
        unset($_GET);
        unset($_POST);
        unset($_COOKIE);
        unset($_REQUEST);
    }
    //if MALICIOUS_DIE, then go die
    if(MALICIOUS_DIE){
        debug_echo($msg);
        die();
    }
}

function ip_waf()
{
    global $white_ip_list,$black_ip_list,$remote_ip;
    
    //if the white_ip_list is set, then receiving the traffic from the ip in the white_ip_list only
    // and the priority of the white list is higher than black list
    if(count($white_ip_list)>0){
        if(!in_array($remote_ip,$white_ip_list)){
            handle_malicious('403 forbidden');
        }
    }else if(count($black_ip_list)>0){
        if(in_array($remote_ip, $black_ip_list)){
            handle_malicious('403 forbidden');
        }
    }
}

function proxy($host,$port,$malicious){
    /*
    this function is used forward the traffic to other server, just like a transparent proxy
    */

    //get basic info
    $method = $_SERVER['REQUEST_METHOD'];
    $url = 'http://' . $host .':'. $port . $_SERVER['REQUEST_URI'];
    $query = $_SERVER['QUERY_STRING'];
    $headers = getallheaders();
    $body = file_get_contents('php://input');
    foreach($_POST as $key=>$value){
        $data[$key] = $value;
    }
    foreach($_GET as $key=>$value){
        $data[$key] = $value;
    }
    foreach($_COOKIE as $key=>$value){
        $data[$key] = $value;
    }
    debug_echo('#### proxy request starts #####');
    debug_var_dump($headers);
    debug_var_dump($body);
    debug_echo('#### proxy request ends #####');

    //send request
    //change the header of host to the value of the real server
    $headers['Host'] = $host .':'. $port;
    // if there is extra output, the accept-encoding should not be gzip
    $headers['Accept-Encoding'] = 'haozigege';
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

    $new_headers = array();
    foreach ($headers as $key => $value) {
        array_push($new_headers, $key.': '.$value);
    }

    curl_setopt($curl, CURLOPT_HTTPHEADER, $new_headers);
    curl_setopt($curl, CURLOPT_HEADER,1);
    if($method=='GET'){
        ;
    }else if($method=='POST'){
        curl_setopt($curl,CURLOPT_POSTFIELDS,$body);
        curl_setopt($curl,CURLOPT_POST,1);
    }else{
        exit('unknown method: '.$method);
    }
    $res = curl_exec($curl);
    $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);

    // record the server response according to the config
    $tmp = substr($res,0,100);
    if(strlen($tmp)==100){
        $tmp = $tmp.'...';
    }
    if($malicious){
        file_put_contents(LOG_FILENAME, "\n".str_replace("\r", "", $tmp)."\n", FILE_APPEND);
    }
    if(ALL_RECORD){
        file_put_contents(LOG_ALL_FILENAME, "\n".str_replace("\r", "", $tmp)."\n", FILE_APPEND);
    }

    $response_headers = substr($res, 0, $headerSize);
    $response_body = substr($res, $headerSize);
    curl_close($curl);
    debug_echo('#### proxy reply starts #####');
    debug_var_dump($response_headers);
    debug_var_dump($response_body);
    debug_echo('#### proxy reply ends #####');

    //update the headers
    $tmp = array_slice(explode("\r\n",$response_headers),1);
    foreach($tmp as $line){
        if($line!==''&& !strstr($line,"Transfer-Encoding")){
            //list($key,$value) = explode(":",$line,2);
            header($line);
        }
    }

    //output the body
    echo $response_body;
    exit();
    
}

switch (WAF_MODE) {
    case 1:
        if(waf()){;}
        break;

    case 2:
        if(waf()){handle_malicious();}
        break;

    case 3:
        if(waf()){ip_waf();}
        break;

    case 4:
        $m = waf();
        proxy(PROXY_HOST,PROXY_PORT,$m);
        break;
    case 5:
    waf();
    ip_waf();
    break;
    default:
        exit('no such mode!');
        break;
}

?>
