<div class="plugin-container">
    <div class="header-box">Options Selector</div>
    <div class="selection-box">
    <table>
        <tr>
            <td>Log Path:</td>
            <td><input name="log_path" type="text" value="hindsight.log"  size=30 /></td>
        </tr>
        <tr>
            <td>Log Level:</td>
            <td>
                <select name="log_level">
                    <option value="debug">Debug (adds per-record detail)</option>
                    <option value="info" selected>Info (default)</option>
                    <option value="warning">Warning</option>
                    <option value="error">Error</option>
                </select>
            </td>
        </tr>
        <tr>
            <td>Timezone:</td>
            <td>
                <select name="timezone">
                    <option value="Pacific/Auckland">New Zealand [+12/+13]</option>
                    <option value="Australia/Sydney">Sydney [+10/+11]</option>
                    <option value="Australia/Adelaide">Adelaide [+9:30/+10:30]</option>
                    <option value="Australia/Darwin">Darwin [+9:30]</option>
                    <option value="Asia/Tokyo">Japan [+9]</option>
                    <option value="Asia/Seoul">South Korea [+9]</option>
                    <option value="Asia/Shanghai">China [+8]</option>
                    <option value="Asia/Singapore">Singapore [+8]</option>
                    <option value="Australia/West">Western Australia [+8]</option>
                    <option value="Asia/Bangkok">Bangkok [+7]</option>
                    <option value="Asia/Jakarta">Jakarta [+7]</option>
                    <option value="Asia/Yangon">Myanmar [+6:30]</option>
                    <option value="Asia/Dhaka">Bangladesh [+6]</option>
                    <option value="Asia/Omsk">Omsk [+6]</option>
                    <option value="Asia/Kathmandu">Nepal [+5:45]</option>
                    <option value="Asia/Kolkata">India [+5:30]</option>
                    <option value="Asia/Colombo">Sri Lanka [+5:30]</option>
                    <option value="Asia/Karachi">Pakistan [+5]</option>
                    <option value="Asia/Dushanbe">Dushanbe [+5]</option>
                    <option value="Asia/Kabul">Afghanistan [+4:30]</option>
                    <option value="Asia/Dubai">Dubai [+4]</option>
                    <option value="Asia/Tehran">Iran [+3:30]</option>
                    <option value="Europe/Moscow">Moscow [+3]</option>
                    <option value="Europe/Istanbul">Turkey [+3]</option>
                    <option value="Asia/Riyadh">Saudi Arabia [+3]</option>
                    <option value="Africa/Nairobi">East Africa [+3]</option>
                    <option value="Europe/Helsinki">Helsinki [+2/+3]</option>
                    <option value="Africa/Cairo">Egypt [+2/+3]</option>
                    <option value="Africa/Johannesburg">South Africa [+2]</option>
                    <option value="Europe/Zurich">Zurich [+1/+2]</option>
                    <option value="Africa/Lagos">West Africa [+1]</option>
                    <option value="Europe/London">London [0/+1]</option>
                    <option value="UTC">UTC [+0:00]</option>
                    <option value="America/Sao_Paulo">Brazil [-3]</option>
                    <option value="America/St_Johns">Newfoundland [-3:30/-2:30]</option>
                    <option value="America/Halifax">Atlantic [-4/-3]</option>
                    <option value="America/Santiago">Chile [-4/-3]</option>
                    <option value="America/New_York">Eastern [-5/-4]</option>
                    <option value="America/Bogota">Colombia [-5]</option>
                    <option value="America/Chicago">Central [-6/-5]</option>
                    <option value="America/Mexico_City">Mexico City [-6]</option>
                    <option value="US/Mountain">Mountain [-7/-6]</option>
                    <option value="America/Phoenix">Arizona [-7]</option>
                    <option value="US/Pacific" selected="selected">Pacific [-8/-7]</option>
                    <option value="America/Anchorage">Alaska [-9/-8]</option>
                    <option value="Pacific/Honolulu">Hawaii [-10]</option>
                    <option value="Pacific/Midway">Midway [-11]</option>
                </select>
            </td>
        </tr>
        <tr>
            <td colspan=2>Copy files before opening? <input name="copy" type="checkbox" value="copy" checked /></td>
        </tr>
        <tr>
            <td>Temp Path:</td>
            <td><input name="temp_dir" type="text" value="hindsight-temp"  size=30 /></td>
        </tr>
    </table>

    </div>
</div>
