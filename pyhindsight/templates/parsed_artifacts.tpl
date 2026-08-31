<div class="results-artifacts-container">
    <div class="header-box">Parsed Artifacts</div>
    <div class="selection-box">
         <center>
         <table width=100%>
            <tr class="results-row">
                <td align="right">Detected {{(browser_type + ' ') if browser_type else ''}}version:</td>
                <td align="right">{{display_version}}</td>
                <td width=4px></td>
            </tr>
         % display_items = list(artifacts_display.keys())
         % status_summary = artifact_status_summary if defined('artifact_status_summary') else {}
         % described = artifact_status_descriptions if defined('artifact_status_descriptions') else {}
         % def cell(key):
         %     # A count of 0 means "parsed, found nothing". Anything else -- failed,
         %     # skipped, or parsed-but-incomplete -- says so instead of showing a bare
         %     # number that reads as a complete result.
         %     statuses = status_summary.get(key)
         %     count = artifacts_counts.get(key)
         %     detail = described.get(key) or ('/'.join(sorted(statuses)) if statuses else '')
         %     if statuses and count is None:
         %         return detail
         %     end
         %     if statuses:
         %         return '{} ({})'.format(count, detail)
         %     end
         %     return 0 if count is None else count
         % end
         % display_order = ['Archived History', 'History', 'History_downloads', 'Cache', 'Application Cache', 'Media Cache', 'GPUCache', 'Cookies', 'Local Storage', 'Bookmarks', 'Autofill', 'Login Data', 'Preferences', 'Extensions', 'Extension Cookies' ]
         % while len(display_order) > 0:
         %   if display_order[0] in display_items:
            <tr class="results-row">
                <td align="right">{{artifacts_display[display_order[0]]}}:</td>
                <td align="right">{{cell(display_order[0])}}</td>
                <td width=4px></td>

            </tr>
         %       display_items.remove(display_order[0])
         %   end
         %   display_order.pop(0)
         % end

         % for artifact in display_items:
            <tr class="results-row">
                <td align="right">{{artifacts_display[artifact]}}:</td>
                <td align="right">{{cell(artifact)}}</td>
                <td width=4px></td>
            </tr>
         % end
         </table>
         </center>
    </div>
</div>