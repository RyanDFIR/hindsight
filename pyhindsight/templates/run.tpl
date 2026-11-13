% include('templates/header.tpl')

        <script>
            function validateForm() {
                var x = document.forms["run"]["profile_path"].value;
                if (x == null || x == "" || x == "required" || x == "C:\\Path\\To\\Input\\Data") {
                    document.forms["run"]["profile_path"].value = "required";
                    document.forms["run"]["profile_path"].style.color = "white";
                    document.forms["run"]["profile_path"].style.backgroundColor = "#81d742";
                    return false;
                }
                var y = document.forms["run"]["cache_path"].value;
                if (y == null || y == "" || y == "(optional - only needed if outside of the profile path)") {
                    document.forms["run"]["cache_path"].value = null
                }
            }

            function cacheInput() {
                var x = document.forms["run"]["cache_path"].value;
                if (x == null || x == "" || x == "(optional - only needed if outside of the profile path)") {
                    document.forms["run"]["cache_path"].value = ""
                    document.forms["run"]["cache_path"].style.color = "black";
                    document.forms["run"]["cache_path"].style.backgroundColor = "white";
                    return false;
                }
            }
        </script>
        <form action="/run" name="run" method="post" onsubmit="return validateForm();">
        <input type="hidden" name="csrf_token" value="{{csrf_token}}">
        <table class="layout-table">
            <tr>
                <td colspan=2 class="inputs-td">
                    <table width=100%>
                        <tr>
                            <td class="h-logo-cell" rowspan=2 width=105>
                                <img src="static/h.png" width=105>
                            </td>
                            <td class="top-name">
                                <h1>Hindsight</h1>
                            </td>
                        </tr>
                        <tr>
                            <td class="top-tagline">Web Artifact Analysis</td>
                        </tr>
                    </table>
                </td>
            </tr>
            <tr>
                <td colspan=2 class="inputs-td">
                    <p>Hindsight is a free tool for analyzing web artifacts. To get started, select the 'Input Type' below and fill out the 'Input Path' field. Review the plugins and options on the right, and hit the 'Run' button at the bottom.
                </td>
            </tr>
            <tr>
                <td class="inputs-td" valign="top">
                    % include('templates/inputs_selector.tpl')
                </td>
                <td class="inputs-td"  valign="top">
                    % include('templates/plugin_selector.tpl')
                    <br>
                    % include('templates/options_selector.tpl')
                    <br>
                    <input value="Run" type="submit" class="button" style="width:100%" />
                </td></tr>
        </table>
        </form>

% include('templates/footer.tpl')
