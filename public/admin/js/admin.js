// Admin Dashboard JavaScript

$(document).ready(function() {
    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        $('.alert').alert('close');
    }, 5000);
    
    // Confirm before dangerous actions
    $('a[href*="delete"], a[href*="revoke"], a[href*="clear"]').on('click', function(e) {
        if (!confirm('Are you sure you want to perform this action?')) {
            e.preventDefault();
        }
    });
    
    // Initialize tooltips
    $('[data-bs-toggle="tooltip"]').tooltip();
    
    // Auto-refresh dashboard every 60 seconds
    if (window.location.pathname === '/admin' || window.location.pathname === '/admin/dashboard') {
        setInterval(function() {
            $.ajax({
                url: '/admin/dashboard/stats',
                type: 'GET',
                success: function(data) {
                    // Update stats cards
                    $('#totalUsers').text(data.total_users);
                    $('#activeUsers').text(data.active_users);
                    $('#activeApiKeys').text(data.active_api_keys);
                    $('#loginsToday').text(data.logins_today);
                }
            });
        }, 60000);
    }
    
    // Export functionality
    $('.export-btn').on('click', function(e) {
        e.preventDefault();
        var format = $(this).data('format');
        var filters = getCurrentFilters();
        window.location.href = '/admin/users/export?format=' + format + '&' + $.param(filters);
    });
    
    // Bulk actions
    $('#bulkActionBtn').on('click', function() {
        var action = $('#bulkActionSelect').val();
        var selectedIds = [];
        
        $('.user-checkbox:checked').each(function() {
            selectedIds.push($(this).val());
        });
        
        if (selectedIds.length === 0) {
            alert('Please select at least one user.');
            return;
        }
        
        if (confirm('Perform ' + action + ' on ' + selectedIds.length + ' user(s)?')) {
            $.ajax({
                url: '/admin/users/bulk-action',
                type: 'POST',
                data: {
                    action: action,
                    ids: selectedIds,
                    _token: $('meta[name="csrf-token"]').attr('content')
                },
                success: function(response) {
                    location.reload();
                },
                error: function() {
                    alert('Error performing bulk action.');
                }
            });
        }
    });
    
    // Real-time notifications (WebSocket example)
    if (typeof io !== 'undefined') {
        var socket = io.connect('http://localhost:3000');
        
        socket.on('admin_notification', function(data) {
            showNotification(data.title, data.message, data.type);
        });
        
        socket.on('user_activity', function(data) {
            // Update recent activity in real-time
            if (window.location.pathname === '/admin') {
                addRecentActivity(data);
            }
        });
    }
    
    // Chart initialization
    if (typeof Chart !== 'undefined') {
        initializeCharts();
    }
});

function getCurrentFilters() {
    var filters = {};
    
    $('form[method="get"] input, form[method="get"] select').each(function() {
        if ($(this).val()) {
            filters[$(this).attr('name')] = $(this).val();
        }
    });
    
    return filters;
}

function showNotification(title, message, type = 'info') {
    var alertClass = 'alert-' + type;
    var icon = '';
    
    switch(type) {
        case 'success': icon = 'fas fa-check-circle'; break;
        case 'warning': icon = 'fas fa-exclamation-triangle'; break;
        case 'danger': icon = 'fas fa-times-circle'; break;
        default: icon = 'fas fa-info-circle';
    }
    
    var notification = $(
        '<div class="alert ' + alertClass + ' alert-dismissible fade show" role="alert">' +
        '<i class="' + icon + ' me-2"></i>' +
        '<strong>' + title + '</strong> ' + message +
        '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>' +
        '</div>'
    );
    
    $('.container-fluid').prepend(notification);
    
    setTimeout(function() {
        notification.alert('close');
    }, 5000);
}

function addRecentActivity(activity) {
    var row = $(
        '<tr>' +
        '<td>' + activity.time + '</td>' +
        '<td><span class="badge bg-' + getBadgeColor(activity.action) + '">' + 
            activity.action.replace(/_/g, ' ').replace(/\b\w/g, function(l) { return l.toUpperCase(); }) +
        '</span></td>' +
        '<td>' + (activity.resource ? activity.resource : '<em>System</em>') + '</td>' +
        '<td>' + (activity.admin ? activity.admin : '<em>System</em>') + '</td>' +
        '<td>' + (activity.user ? activity.user : '') + '</td>' +
        '<td><code>' + activity.ip + '</code></td>' +
        '</tr>'
    );
    
    $('#recentActivityTable tbody').prepend(row);
    
    // Limit to 20 rows
    if ($('#recentActivityTable tbody tr').length > 20) {
        $('#recentActivityTable tbody tr:last').remove();
    }
}

function getBadgeColor(action) {
    if (action.startsWith('user_create')) return 'success';
    if (action.startsWith('user_update')) return 'info';
    if (action.startsWith('user_delete')) return 'danger';
    if (action.startsWith('login')) return 'warning';
    return 'secondary';
}

function initializeCharts() {
    // User registration chart
    var ctx = document.getElementById('userRegistrationsChart');
    if (ctx) {
        $.get('/admin/dashboard/chart/registrations', function(data) {
            new Chart(ctx, {
                type: 'line',
                data: data,
                options: {
                    responsive: true,
                    plugins: {
                        legend: { display: true },
                        title: { display: true, text: 'User Registrations' }
                    }
                }
            });
        });
    }
    
    // Login activity chart
    var ctx2 = document.getElementById('loginActivityChart');
    if (ctx2) {
        $.get('/admin/dashboard/chart/logins', function(data) {
            new Chart(ctx2, {
                type: 'bar',
                data: data,
                options: {
                    responsive: true,
                    plugins: {
                        legend: { display: true },
                        title: { display: true, text: 'Login Activity' }
                    }
                }
            });
        });
    }
}

// Session timeout warning
let idleTime = 0;
$(document).ready(function() {
    // Increment idle time every minute
    let idleInterval = setInterval(timerIncrement, 60000);
    
    // Reset idle time on activity
    $(this).on('mousemove keypress click', function() {
        idleTime = 0;
    });
});

function timerIncrement() {
    idleTime++;
    if (idleTime > 29) { // 30 minutes
        showSessionWarning();
    }
}

function showSessionWarning() {
    if (!$('#sessionWarningModal').length) {
        var modal = $(
            '<div class="modal fade" id="sessionWarningModal" tabindex="-1">' +
            '<div class="modal-dialog">' +
            '<div class="modal-content">' +
            '<div class="modal-header">' +
            '<h5 class="modal-title">Session Timeout Warning</h5>' +
            '<button type="button" class="btn-close" data-bs-dismiss="modal"></button>' +
            '</div>' +
            '<div class="modal-body">' +
            '<p>Your session will expire in 5 minutes due to inactivity.</p>' +
            '<p>Do you want to continue your session?</p>' +
            '</div>' +
            '<div class="modal-footer">' +
            '<button type="button" class="btn btn-primary" id="continueSession">Continue Session</button>' +
            '<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Logout</button>' +
            '</div>' +
            '</div>' +
            '</div>' +
            '</div>'
        );
        
        $('body').append(modal);
        
        modal.modal('show');
        
        $('#continueSession').on('click', function() {
            $.post('/admin/session/refresh', function() {
                idleTime = 0;
                modal.modal('hide');
            });
        });
        
        modal.on('hidden.bs.modal', function() {
            window.location.href = '/admin/logout';
        });
        
        // Auto-logout after 5 more minutes
        setTimeout(function() {
            if ($('#sessionWarningModal').is(':visible')) {
                window.location.href = '/admin/logout';
            }
        }, 300000);
    }
}