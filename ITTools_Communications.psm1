# Author unknown
function Send-EMail {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [Alias('PsPath')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Attachments},

        [ValidateNotNullOrEmpty()]
        [Collections.HashTable]
        ${InlineAttachments},
        
        [ValidateNotNullOrEmpty()]
        [Net.Mail.MailAddress[]]
        ${Bcc},
    
        [Parameter(Position=2)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Body},
        
        [Alias('BAH')]
        [switch]
        ${BodyAsHtml},
    
        [ValidateNotNullOrEmpty()]
        [Net.Mail.MailAddress[]]
        ${Cc},
    
        [Alias('DNO')]
        [ValidateNotNullOrEmpty()]
        [Net.Mail.DeliveryNotificationOptions]
        ${DeliveryNotificationOption},
    
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Net.Mail.MailAddress]
        ${From},
    
        [Parameter(Mandatory = $true, Position = 3)]
        [Alias('ComputerName')]
        [string]
        ${SmtpServer},
    
        [ValidateNotNullOrEmpty()]
        [Net.Mail.MailPriority]
        ${Priority},
        
        [Parameter(Mandatory=$true, Position=1)]
        [Alias('sub')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Subject},
    
        [Parameter(Mandatory=$true, Position=0)]
        [Net.Mail.MailAddress[]]
        ${To},
    
        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        ${Credential},
    
        [switch]
        ${UseSsl},
    
        [ValidateRange(0, 2147483647)]
        [int]
        ${Port} = 25
    )
    
    begin
    {
        function FileNameToContentType
        {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [string]
                $FileName
            )

            $mimeMappings = @{
                '.323' = 'text/h323'
                '.aaf' = 'application/octet-stream'
                '.aca' = 'application/octet-stream'
                '.accdb' = 'application/msaccess'
                '.accde' = 'application/msaccess'
                '.accdt' = 'application/msaccess'
                '.acx' = 'application/internet-property-stream'
                '.afm' = 'application/octet-stream'
                '.ai' = 'application/postscript'
                '.aif' = 'audio/x-aiff'
                '.aifc' = 'audio/aiff'
                '.aiff' = 'audio/aiff'
                '.application' = 'application/x-ms-application'
                '.art' = 'image/x-jg'
                '.asd' = 'application/octet-stream'
                '.asf' = 'video/x-ms-asf'
                '.asi' = 'application/octet-stream'
                '.asm' = 'text/plain'
                '.asr' = 'video/x-ms-asf'
                '.asx' = 'video/x-ms-asf'
                '.atom' = 'application/atom+xml'
                '.au' = 'audio/basic'
                '.avi' = 'video/x-msvideo'
                '.axs' = 'application/olescript'
                '.bas' = 'text/plain'
                '.bcpio' = 'application/x-bcpio'
                '.bin' = 'application/octet-stream'
                '.bmp' = 'image/bmp'
                '.c' = 'text/plain'
                '.cab' = 'application/octet-stream'
                '.calx' = 'application/vnd.ms-office.calx'
                '.cat' = 'application/vnd.ms-pki.seccat'
                '.cdf' = 'application/x-cdf'
                '.chm' = 'application/octet-stream'
                '.class' = 'application/x-java-applet'
                '.clp' = 'application/x-msclip'
                '.cmx' = 'image/x-cmx'
                '.cnf' = 'text/plain'
                '.cod' = 'image/cis-cod'
                '.cpio' = 'application/x-cpio'
                '.cpp' = 'text/plain'
                '.crd' = 'application/x-mscardfile'
                '.crl' = 'application/pkix-crl'
                '.crt' = 'application/x-x509-ca-cert'
                '.csh' = 'application/x-csh'
                '.css' = 'text/css'
                '.csv' = 'application/octet-stream'
                '.cur' = 'application/octet-stream'
                '.dcr' = 'application/x-director'
                '.deploy' = 'application/octet-stream'
                '.der' = 'application/x-x509-ca-cert'
                '.dib' = 'image/bmp'
                '.dir' = 'application/x-director'
                '.disco' = 'text/xml'
                '.dll' = 'application/x-msdownload'
                '.dll.config' = 'text/xml'
                '.dlm' = 'text/dlm'
                '.doc' = 'application/msword'
                '.docm' = 'application/vnd.ms-word.document.macroEnabled.12'
                '.docx' = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                '.dot' = 'application/msword'
                '.dotm' = 'application/vnd.ms-word.template.macroEnabled.12'
                '.dotx' = 'application/vnd.openxmlformats-officedocument.wordprocessingml.template'
                '.dsp' = 'application/octet-stream'
                '.dtd' = 'text/xml'
                '.dvi' = 'application/x-dvi'
                '.dwf' = 'drawing/x-dwf'
                '.dwp' = 'application/octet-stream'
                '.dxr' = 'application/x-director'
                '.eml' = 'message/rfc822'
                '.emz' = 'application/octet-stream'
                '.eot' = 'application/octet-stream'
                '.eps' = 'application/postscript'
                '.etx' = 'text/x-setext'
                '.evy' = 'application/envoy'
                '.exe' = 'application/octet-stream'
                '.exe.config' = 'text/xml'
                '.fdf' = 'application/vnd.fdf'
                '.fif' = 'application/fractals'
                '.fla' = 'application/octet-stream'
                '.flr' = 'x-world/x-vrml'
                '.flv' = 'video/x-flv'
                '.gif' = 'image/gif'
                '.gtar' = 'application/x-gtar'
                '.gz' = 'application/x-gzip'
                '.h' = 'text/plain'
                '.hdf' = 'application/x-hdf'
                '.hdml' = 'text/x-hdml'
                '.hhc' = 'application/x-oleobject'
                '.hhk' = 'application/octet-stream'
                '.hhp' = 'application/octet-stream'
                '.hlp' = 'application/winhlp'
                '.hqx' = 'application/mac-binhex40'
                '.hta' = 'application/hta'
                '.htc' = 'text/x-component'
                '.htm' = 'text/html'
                '.html' = 'text/html'
                '.htt' = 'text/webviewhtml'
                '.hxt' = 'text/html'
                '.ico' = 'image/x-icon'
                '.ics' = 'application/octet-stream'
                '.ief' = 'image/ief'
                '.iii' = 'application/x-iphone'
                '.inf' = 'application/octet-stream'
                '.ins' = 'application/x-internet-signup'
                '.isp' = 'application/x-internet-signup'
                '.IVF' = 'video/x-ivf'
                '.jar' = 'application/java-archive'
                '.java' = 'application/octet-stream'
                '.jck' = 'application/liquidmotion'
                '.jcz' = 'application/liquidmotion'
                '.jfif' = 'image/pjpeg'
                '.jpb' = 'application/octet-stream'
                '.jpe' = 'image/jpeg'
                '.jpeg' = 'image/jpeg'
                '.jpg' = 'image/jpeg'
                '.js' = 'application/x-javascript'
                '.jsx' = 'text/jscript'
                '.latex' = 'application/x-latex'
                '.lit' = 'application/x-ms-reader'
                '.lpk' = 'application/octet-stream'
                '.lsf' = 'video/x-la-asf'
                '.lsx' = 'video/x-la-asf'
                '.lzh' = 'application/octet-stream'
                '.m13' = 'application/x-msmediaview'
                '.m14' = 'application/x-msmediaview'
                '.m1v' = 'video/mpeg'
                '.m3u' = 'audio/x-mpegurl'
                '.man' = 'application/x-troff-man'
                '.manifest' = 'application/x-ms-manifest'
                '.map' = 'text/plain'
                '.mdb' = 'application/x-msaccess'
                '.mdp' = 'application/octet-stream'
                '.me' = 'application/x-troff-me'
                '.mht' = 'message/rfc822'
                '.mhtml' = 'message/rfc822'
                '.mid' = 'audio/mid'
                '.midi' = 'audio/mid'
                '.mix' = 'application/octet-stream'
                '.mmf' = 'application/x-smaf'
                '.mno' = 'text/xml'
                '.mny' = 'application/x-msmoney'
                '.mov' = 'video/quicktime'
                '.movie' = 'video/x-sgi-movie'
                '.mp2' = 'video/mpeg'
                '.mp3' = 'audio/mpeg'
                '.mpa' = 'video/mpeg'
                '.mpe' = 'video/mpeg'
                '.mpeg' = 'video/mpeg'
                '.mpg' = 'video/mpeg'
                '.mpp' = 'application/vnd.ms-project'
                '.mpv2' = 'video/mpeg'
                '.ms' = 'application/x-troff-ms'
                '.msi' = 'application/octet-stream'
                '.mso' = 'application/octet-stream'
                '.mvb' = 'application/x-msmediaview'
                '.mvc' = 'application/x-miva-compiled'
                '.nc' = 'application/x-netcdf'
                '.nsc' = 'video/x-ms-asf'
                '.nws' = 'message/rfc822'
                '.ocx' = 'application/octet-stream'
                '.oda' = 'application/oda'
                '.odc' = 'text/x-ms-odc'
                '.ods' = 'application/oleobject'
                '.one' = 'application/onenote'
                '.onea' = 'application/onenote'
                '.onetoc' = 'application/onenote'
                '.onetoc2' = 'application/onenote'
                '.onetmp' = 'application/onenote'
                '.onepkg' = 'application/onenote'
                '.osdx' = 'application/opensearchdescription+xml'
                '.p10' = 'application/pkcs10'
                '.p12' = 'application/x-pkcs12'
                '.p7b' = 'application/x-pkcs7-certificates'
                '.p7c' = 'application/pkcs7-mime'
                '.p7m' = 'application/pkcs7-mime'
                '.p7r' = 'application/x-pkcs7-certreqresp'
                '.p7s' = 'application/pkcs7-signature'
                '.pbm' = 'image/x-portable-bitmap'
                '.pcx' = 'application/octet-stream'
                '.pcz' = 'application/octet-stream'
                '.pdf' = 'application/pdf'
                '.pfb' = 'application/octet-stream'
                '.pfm' = 'application/octet-stream'
                '.pfx' = 'application/x-pkcs12'
                '.pgm' = 'image/x-portable-graymap'
                '.pko' = 'application/vnd.ms-pki.pko'
                '.pma' = 'application/x-perfmon'
                '.pmc' = 'application/x-perfmon'
                '.pml' = 'application/x-perfmon'
                '.pmr' = 'application/x-perfmon'
                '.pmw' = 'application/x-perfmon'
                '.png' = 'image/png'
                '.pnm' = 'image/x-portable-anymap'
                '.pnz' = 'image/png'
                '.pot' = 'application/vnd.ms-powerpoint'
                '.potm' = 'application/vnd.ms-powerpoint.template.macroEnabled.12'
                '.potx' = 'application/vnd.openxmlformats-officedocument.presentationml.template'
                '.ppam' = 'application/vnd.ms-powerpoint.addin.macroEnabled.12'
                '.ppm' = 'image/x-portable-pixmap'
                '.pps' = 'application/vnd.ms-powerpoint'
                '.ppsm' = 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12'
                '.ppsx' = 'application/vnd.openxmlformats-officedocument.presentationml.slideshow'
                '.ppt' = 'application/vnd.ms-powerpoint'
                '.pptm' = 'application/vnd.ms-powerpoint.presentation.macroEnabled.12'
                '.pptx' = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
                '.prf' = 'application/pics-rules'
                '.prm' = 'application/octet-stream'
                '.prx' = 'application/octet-stream'
                '.ps' = 'application/postscript'
                '.psd' = 'application/octet-stream'
                '.psm' = 'application/octet-stream'
                '.psp' = 'application/octet-stream'
                '.pub' = 'application/x-mspublisher'
                '.qt' = 'video/quicktime'
                '.qtl' = 'application/x-quicktimeplayer'
                '.qxd' = 'application/octet-stream'
                '.ra' = 'audio/x-pn-realaudio'
                '.ram' = 'audio/x-pn-realaudio'
                '.rar' = 'application/octet-stream'
                '.ras' = 'image/x-cmu-raster'
                '.rf' = 'image/vnd.rn-realflash'
                '.rgb' = 'image/x-rgb'
                '.rm' = 'application/vnd.rn-realmedia'
                '.rmi' = 'audio/mid'
                '.roff' = 'application/x-troff'
                '.rpm' = 'audio/x-pn-realaudio-plugin'
                '.rtf' = 'application/rtf'
                '.rtx' = 'text/richtext'
                '.scd' = 'application/x-msschedule'
                '.sct' = 'text/scriptlet'
                '.sea' = 'application/octet-stream'
                '.setpay' = 'application/set-payment-initiation'
                '.setreg' = 'application/set-registration-initiation'
                '.sgml' = 'text/sgml'
                '.sh' = 'application/x-sh'
                '.shar' = 'application/x-shar'
                '.sit' = 'application/x-stuffit'
                '.sldm' = 'application/vnd.ms-powerpoint.slide.macroEnabled.12'
                '.sldx' = 'application/vnd.openxmlformats-officedocument.presentationml.slide'
                '.smd' = 'audio/x-smd'
                '.smi' = 'application/octet-stream'
                '.smx' = 'audio/x-smd'
                '.smz' = 'audio/x-smd'
                '.snd' = 'audio/basic'
                '.snp' = 'application/octet-stream'
                '.spc' = 'application/x-pkcs7-certificates'
                '.spl' = 'application/futuresplash'
                '.src' = 'application/x-wais-source'
                '.ssm' = 'application/streamingmedia'
                '.sst' = 'application/vnd.ms-pki.certstore'
                '.stl' = 'application/vnd.ms-pki.stl'
                '.sv4cpio' = 'application/x-sv4cpio'
                '.sv4crc' = 'application/x-sv4crc'
                '.swf' = 'application/x-shockwave-flash'
                '.t' = 'application/x-troff'
                '.tar' = 'application/x-tar'
                '.tcl' = 'application/x-tcl'
                '.tex' = 'application/x-tex'
                '.texi' = 'application/x-texinfo'
                '.texinfo' = 'application/x-texinfo'
                '.tgz' = 'application/x-compressed'
                '.thmx' = 'application/vnd.ms-officetheme'
                '.thn' = 'application/octet-stream'
                '.tif' = 'image/tiff'
                '.tiff' = 'image/tiff'
                '.toc' = 'application/octet-stream'
                '.tr' = 'application/x-troff'
                '.trm' = 'application/x-msterminal'
                '.tsv' = 'text/tab-separated-values'
                '.ttf' = 'application/octet-stream'
                '.txt' = 'text/plain'
                '.u32' = 'application/octet-stream'
                '.uls' = 'text/iuls'
                '.ustar' = 'application/x-ustar'
                '.vbs' = 'text/vbscript'
                '.vcf' = 'text/x-vcard'
                '.vcs' = 'text/plain'
                '.vdx' = 'application/vnd.ms-visio.viewer'
                '.vml' = 'text/xml'
                '.vsd' = 'application/vnd.visio'
                '.vss' = 'application/vnd.visio'
                '.vst' = 'application/vnd.visio'
                '.vsto' = 'application/x-ms-vsto'
                '.vsw' = 'application/vnd.visio'
                '.vsx' = 'application/vnd.visio'
                '.vtx' = 'application/vnd.visio'
                '.wav' = 'audio/wav'
                '.wax' = 'audio/x-ms-wax'
                '.wbmp' = 'image/vnd.wap.wbmp'
                '.wcm' = 'application/vnd.ms-works'
                '.wdb' = 'application/vnd.ms-works'
                '.wks' = 'application/vnd.ms-works'
                '.wm' = 'video/x-ms-wm'
                '.wma' = 'audio/x-ms-wma'
                '.wmd' = 'application/x-ms-wmd'
                '.wmf' = 'application/x-msmetafile'
                '.wml' = 'text/vnd.wap.wml'
                '.wmlc' = 'application/vnd.wap.wmlc'
                '.wmls' = 'text/vnd.wap.wmlscript'
                '.wmlsc' = 'application/vnd.wap.wmlscriptc'
                '.wmp' = 'video/x-ms-wmp'
                '.wmv' = 'video/x-ms-wmv'
                '.wmx' = 'video/x-ms-wmx'
                '.wmz' = 'application/x-ms-wmz'
                '.wps' = 'application/vnd.ms-works'
                '.wri' = 'application/x-mswrite'
                '.wrl' = 'x-world/x-vrml'
                '.wrz' = 'x-world/x-vrml'
                '.wsdl' = 'text/xml'
                '.wvx' = 'video/x-ms-wvx'
                '.x' = 'application/directx'
                '.xaf' = 'x-world/x-vrml'
                '.xaml' = 'application/xaml+xml'
                '.xap' = 'application/x-silverlight-app'
                '.xbap' = 'application/x-ms-xbap'
                '.xbm' = 'image/x-xbitmap'
                '.xdr' = 'text/plain'
                '.xla' = 'application/vnd.ms-excel'
                '.xlam' = 'application/vnd.ms-excel.addin.macroEnabled.12'
                '.xlc' = 'application/vnd.ms-excel'
                '.xlm' = 'application/vnd.ms-excel'
                '.xls' = 'application/vnd.ms-excel'
                '.xlsb' = 'application/vnd.ms-excel.sheet.binary.macroEnabled.12'
                '.xlsm' = 'application/vnd.ms-excel.sheet.macroEnabled.12'
                '.xlsx' = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                '.xlt' = 'application/vnd.ms-excel'
                '.xltm' = 'application/vnd.ms-excel.template.macroEnabled.12'
                '.xltx' = 'application/vnd.openxmlformats-officedocument.spreadsheetml.template'
                '.xlw' = 'application/vnd.ms-excel'
                '.xml' = 'text/xml'
                '.xof' = 'x-world/x-vrml'
                '.xpm' = 'image/x-xpixmap'
                '.xps' = 'application/vnd.ms-xpsdocument'
                '.xsd' = 'text/xml'
                '.xsf' = 'text/xml'
                '.xsl' = 'text/xml'
                '.xslt' = 'text/xml'
                '.xsn' = 'application/octet-stream'
                '.xtp' = 'application/octet-stream'
                '.xwd' = 'image/x-xwindowdump'
                '.z' = 'application/x-compress'
                '.zip' = 'application/x-zip-compressed'
            }

            $extension = [System.IO.Path]::GetExtension($FileName)
            $contentType = $mimeMappings[$extension]

            if ([string]::IsNullOrEmpty($contentType))
            {
                return New-Object System.Net.Mime.ContentType
            }
            else
            {
                return New-Object System.Net.Mime.ContentType($contentType)
            }
        }

        try
        {
            $_smtpClient = New-Object Net.Mail.SmtpClient
        
            $_smtpClient.Host = $SmtpServer
            $_smtpClient.Port = $Port
            $_smtpClient.EnableSsl = $UseSsl

            if ($null -ne $Credential)
            {
                # In PowerShell 2.0, assigning the results of GetNetworkCredential() to the SMTP client sometimes fails (with gmail, in testing), but
                # building a new NetworkCredential object containing only the UserName and Password works okay.

                $_tempCred = $Credential.GetNetworkCredential()
                $_smtpClient.Credentials = New-Object Net.NetworkCredential($Credential.UserName, $_tempCred.Password)
            }
            else
            {
                $_smtpClient.UseDefaultCredentials = $true
            }

            $_message = New-Object Net.Mail.MailMessage
        
            $_message.From = $From
            $_message.Subject = $Subject
            
            if ($BodyAsHtml)
            {
                $_bodyPart = [Net.Mail.AlternateView]::CreateAlternateViewFromString($Body, 'text/html')
            }
            else
            {
                $_bodyPart = [Net.Mail.AlternateView]::CreateAlternateViewFromString($Body, 'text/plain')
            }   

            $_message.AlternateViews.Add($_bodyPart)

            if ($PSBoundParameters.ContainsKey('DeliveryNotificationOption')) { $_message.DeliveryNotificationOptions = $DeliveryNotificationOption }
            if ($PSBoundParameters.ContainsKey('Priority')) { $_message.Priority = $Priority }

            foreach ($_address in $To)
            {
                if (-not $_message.To.Contains($_address)) { $_message.To.Add($_address) }
            }

            if ($null -ne $Cc)
            {
                foreach ($_address in $Cc)
                {
                    if (-not $_message.CC.Contains($_address)) { $_message.CC.Add($_address) }
                }
            }

            if ($null -ne $Bcc)
            {
                foreach ($_address in $Bcc)
                {
                    if (-not $_message.Bcc.Contains($_address)) { $_message.Bcc.Add($_address) }
                }
            }
        }
        catch
        {
            $_message.Dispose()
            throw
        }

        if ($PSBoundParameters.ContainsKey('InlineAttachments'))
        {
            foreach ($_entry in $InlineAttachments.GetEnumerator())
            {
                $_file = $_entry.Value.ToString()
                
                if ([string]::IsNullOrEmpty($_file))
                {
                    $_message.Dispose()
                    throw "Send-EMail: Values in the InlineAttachments table cannot be null."
                }

                try
                {
                    $_contentType = FileNameToContentType -FileName $_file
                    $_attachment = New-Object Net.Mail.LinkedResource($_file, $_contentType)
                    $_attachment.ContentId = $_entry.Key

                    $_bodyPart.LinkedResources.Add($_attachment)
                }
                catch
                {
                    $_message.Dispose()
                    throw
                }
            }
        }
    }

    process
    {
        if ($null -ne $Attachments)
        {
            foreach ($_file in $Attachments)
            {
                try
                {
                    $_contentType = FileNameToContentType -FileName $_file
                    $_message.Attachments.Add((New-Object Net.Mail.Attachment($_file, $_contentType)))
                }
                catch
                {
                    $_message.Dispose()
                    throw
                }
            }
        }
    }
    
    end
    {
        try
        {
            $_smtpClient.Send($_message)
        }
        catch
        {
            throw
        }
        finally
        {
            $_message.Dispose()
        }
    }

}


function Connect-CMServer {
    [CmdletBinding()]
    param (
        # Primary site server FQDN
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [Alias('DnsHostName','ComputerName')]
        [string]$SiteServer,

        # SMS site code
        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [string]$SiteCode = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client").AssignedSiteCode
    )

    if (!(Test-Path 'Env:\SMS_ADMIN_UI_PATH')) {
        Write-Error -Message 'Seems like MECM management console is not installed on this computer.' `
            -Category ObjectNotFound `
            -TargetObject 'Env:\SMS_ADMIN_UI_PATH' `
            -RecommendedAction 'Install management console from cd.latest'
        return
    }

    Import-Module ((Split-Path $env:SMS_ADMIN_UI_PATH) + "\ConfigurationManager.psd1") -Scope Global
    try {
        Get-PSDrive -Name $SiteCode -ErrorAction Stop -Scope Global
    }
    catch [System.Management.Automation.DriveNotFoundException] {
        $Global:Error.RemoveAt(0)
        New-PSDrive -Name $SiteCode -PSProvider "CMSite" -Root $SiteServer -Description "MS MECM" -Scope Global
    }
    Set-Location -Path "$($SiteCode):\"
}


##############################################################
####                 Connection using DW MRC              ####
##############################################################

function Connect-DWClient {
    [CmdletBinding()]
    param (
        [Parameter(mandatory=$True)][string]$Target,
        [Parameter(mandatory=$false)][Switch]$Force,
        [Parameter(mandatory=$false)][Switch]$Polite
    )


    # Test target PC availability
    try {
        Test-Connection $Target -Count 1 -ErrorAction Stop
    }
    catch {
        Write-Host "Host is unavaliable." -ForegroundColor Red -BackgroundColor Black
        return
    }

    # Change remote registry service start mode to auto and run it
    cmd /c "sc \\$Target config remoteregistry start=auto"
    cmd /c "sc \\$Target start remoteregistry"

    # Change registry:
    # allowing dameware service to start in safe mode
    reg add "\\$Target\HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\dwmrcs" /t REG_SZ /d Service /f

    if ($Polite) {
        # Enable request to user before connection
        reg add "\\$Target\HKLM\SOFTWARE\DameWare Development\Mini Remote Control Service\Settings" /v "Permission Required" /t REG_DWORD /d 1 /f
    }
    if ($Force) {
        # Disable request to user before connection
        reg add "\\$Target\HKLM\SOFTWARE\DameWare Development\Mini Remote Control Service\Settings" /v "Permission Required" /t REG_DWORD /d 0 /f
    }

    # Run the connection. Close the application when disconnected
    Start-Sleep -Seconds 1
    Start-Process "${env:ProgramFiles(x86)}\SolarWinds\DameWare Remote Support\DWRCC.exe" -ArgumentList "-h -c -x -m:$Target"

    # Return registry value.
    if ($Force) {
        Start-Job -ScriptBlock {
            Start-Sleep -Seconds 30
            reg add "\\$Target\HKLM\SOFTWARE\DameWare Development\Mini Remote Control Service\Settings" /v "Permission Required" /t REG_DWORD /d 1 /f
        }
    }
}



##############################################################
####           Connection using UltraVNC Viewer           ####
##############################################################

function Connect-VNCClient {
    param (
        # Parameter help description
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string]$Computername
    )

    Start-Process "$env:ProgramFiles\UltraVNC\vncviewer.exe" -ArgumentList "-connect $using:Computername -autoscaling -user $env:USERNAME"
}


##############################################################
####      Connect to exchange server via powershell       ####
##############################################################
function New-ExchangeSession {
    param (
        # Exchange server FQDN.
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [string]$Domain = $env:USERDNSDOMAIN,

        # Exchange server FQDN.
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [string]$ExchangeServer
    )

    if (!$ExchangeServer) {
        $ExchangeServers = @()
        try {
            $Root = [adsi]"LDAP://$(($Domain.ToLower().Split('.') | ForEach-Object {"DC=$PSItem"}) -join ',')"
            $Searcher = [adsisearcher]::new($Root)
        }
        catch {
            throw "Cannot contact domain $($Domain) via LDAP. $($Error[0].Exception.Message)"
        }

        try {
            $Searcher.Filter = "(&(objectClass=group)(cn=Exchange servers))"
            $ExchangeServersGroup = $Searcher.FindOne().GetDirectoryEntry().member
        }
        catch {
            throw "Cannot find Exchange server $($ExchangeServer) in forest $Domain. $($Error[0].Exception.Message)"
        }

        foreach ($Member in $ExchangeServersGroup) {
            $ExchSearcher = [adsisearcher]"(&(objectClass=computer)(distinguishedName=$Member))"
            [void]($ExchSearcher.PropertiesToLoad.Add('dNSHostName'))
            $ExchangeSearchResult = $ExchSearcher.FindOne()
            if ($ExchangeSearchResult) {
                $ExchangeServers += $ExchangeSearchResult.GetDirectoryEntry().dNSHostName
                Write-Verbose "$Member is exchange server."
            }
            else {
                Write-Verbose "$Member is not server."
            }
        }
        $ExchangeServer = $ExchangeServers[0]
    }

    $DegrExSess = Get-PSSession | Where-Object {($ComputerName -eq $ExchangeServer) -and ($PSItem.State -ne "Opened")}
    if ($DegrExSess) {
        $DegrExSess | Remove-PSSession -Confirm:$false
    }
    $OpenedExSess = Get-PSSession | Where-Object {($PSItem.ComputerName -eq $ExchangeServer) -and ($PSItem.State -eq "Opened")}
    if (!$OpenedExSess) {
        try {
            $global:Exchange = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeServer/PowerShell/ -Authentication Kerberos
        }
        catch {
            throw
        }
    }
    else {
        $global:Exchange = $OpenedExSess[0]
    }

    return $global:Exchange
}


##############################################################
####     Shadow connection to Win10/Server2016+ hosts     ####
##############################################################
function New-ShadowConnection {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [switch]$ViewOnly
    )
    $Sessions = @()
    Get-QWinSta $ComputerName | Where-Object {$PSItem.State -eq "Active"} | ForEach-Object {$Sessions += $PSItem}
    if ($Sessions.count -gt 1) {
        $Sessions | Select-Object ID,UserName | Out-Host
        $SessionID = Read-Host "Type session ID"
    }
    else {
        $SessionID = $Sessions.ID
    }

    $ArgList = @(
        "/v:$ComputerName",
        "/shadow:$SessionID",
        "/NoConsentPrompt"
    )
    if (!$ViewOnly) {
        $ArgList += "/Control"
    }
    Start-Process mstsc.exe -ArgumentList $ArgList
}




##############################################################
####               Send Wake-on-LAN package               ####
##############################################################
function Send-WOL {
    <#
        .SYNOPSIS
            Send a WOL packet to a broadcast address
        .PARAMETER MAC
        The MAC address of the device that need to wake up
        .PARAMETER ComputerName
        Name of the compurer, that need to wake up. IPAddress defines automaticaly.
        .PARAMETER IP
        The IP address where the WOL packet will be sent to
        .EXAMPLE
        Send-WOL -mac 00:11:22:33:44:55 -ip 192.168.2.100
    #>
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    param(
        [Parameter(
            Mandatory=$True,
            Position = 1,
            ParameterSetName = 'MAC'
        )]
        [ValidatePattern(
            "(^[a-f0-9\*]{1,12}$)|(^[a-f0-9\-\*]{1,14}$)|(^[a-f0-9\:\*]{1,17}$)|(^[a-f0-9\-\*]{1,17}$)"
        )]
        [string]$MAC,

        [Parameter(
            Mandatory=$True,
            Position = 1,
            ParameterSetName = 'ComputerName'
        )]
        [string]$ComputerName,

        # Parameter help description
        [Parameter(
            Mandatory = $false
        )]
        [ValidateScript(
            {
                try {
                    [ipaddress]$PSItem
                    return $true
                }
                catch {
                    throw "$PSItem is not valid ip address"
                }
            }
        )]
        [string]$IPAddress,
        [int]$Port = 9
    )


    if (($Computername) -and ($ComputerName -notmatch "([0-9a-f]{2}[:\-]?){5}[0-9a-f]{2}")) {
        try {
            $IPAddressFromDNS = (Resolve-DnsName $ComputerName -ErrorAction Stop).IPAddress
        }
        catch {
            Write-Error -Message "Can't resolve name to IP address. Please, try by MAC." -Category InvalidData -TargetObject "$ComputerName"
            break
        }
        $DHCPServerName = (Resolve-DnsName (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$PSItem.DnsDomain -eq $env:USERDNSDOMAIN}).DHCPServer).NameHost
        $ScopeID = $IPAddressFromDNS -replace "\.\d{1,3}$",'.0'
        if (!$IPAddress) {
            $IPAddress = $IPAddressFromDNS -replace "\.\d{1,3}$",'.255'
        }

        try {
            $MAC = (Get-DhcpServerv4Lease -ComputerName $DHCPServerName -ScopeId $ScopeID -ErrorAction Stop| Where-Object {$PSItem.IPAddress -eq $IPAddressFromDNS}).ClientId
        }
        catch {
            Write-Error -Message "Can't find IP lease on $DHCPServerName. Please, try by MAC." -Category InvalidData -TargetObject "$IPAddressFromDNS"
            break
        }
    }

    else {
        if (!$IPAddress) {
            $IPAddress = "255.255.255.255"
        }
    }

    $Broadcast = [Net.IPAddress]::Parse($IPAddress)

    $MAC=(($MAC.Replace(":","")).Replace("-","")).Replace(".","")
    $Target=0,2,4,6,8,10 | ForEach-Object {[convert]::ToByte($MAC.Substring($PSItem,2),16)}
    $Packet = (,[byte]255 * 6) + ($Target * 16)

    $UDPClient = New-Object System.Net.Sockets.UdpClient
    $UDPClient.Connect($Broadcast,$Port)
    [void]$UDPClient.Send($Packet, 102)
}
