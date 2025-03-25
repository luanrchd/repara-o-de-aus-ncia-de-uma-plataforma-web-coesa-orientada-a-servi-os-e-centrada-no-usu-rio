

```php
// database/seeders/RolesAndPermissionsSeeder.php
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
use App\Models\User; // Assuming User model exists

class RolesAndPermissionsSeeder extends Seeder
{
    public function run()
    {
        // Reset cached roles and permissions
        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();

        // Create Permissions
        Permission::create(['name' => 'manage users']);
        Permission::create(['name' => 'manage courses']);
        Permission::create(['name' => 'create announcements']);
        Permission::create(['name' => 'publish announcements']); // Maybe separate create/publish
        Permission::create(['name' => 'view all announcements']);
        Permission::create(['name' => 'upload resources']);
        Permission::create(['name' => 'manage own resources']);
        Permission::create(['name' => 'view course resources']);
        Permission::create(['name' => 'manage calendar events']);
        Permission::create(['name' => 'view calendar']);
        Permission::create(['name' => 'send messages']);
        Permission::create(['name' => 'view own grades']); // Example specific permission
        Permission::create(['name' => 'manage grades']);   // Example specific permission

        // Create Roles and Assign Permissions
        $admin = Role::create(['name' => 'Admin']);
        $admin->givePermissionTo(Permission::all()); // Admin gets all

        $teacher = Role::create(['name' => 'Teacher']);
        $teacher->givePermissionTo([
            'create announcements',
            'publish announcements', // Teachers can publish their own
            'upload resources',
            'manage own resources',
            'view course resources',
            'manage calendar events', // Add events for their courses
            'view calendar',
            'send messages',
            'manage grades', // For their subjects/courses
        ]);

        $student = Role::create(['name' => 'Student']);
        $student->givePermissionTo([
            'view course resources',
            'view calendar',
            'view own grades',
        ]);

        $parent = Role::create(['name' => 'Parent']);
        $parent->givePermissionTo([
            'view calendar', // View general + child's relevant events
            // Permissions might be linked dynamically to their child's permissions
            // 'view child grades', 'view child resources' - Needs custom logic beyond Spatie basics
        ]);

        // You would assign roles to users during registration or via an admin panel
        // Example: $user = User::find(1); $user->assignRole('Admin');
    }
}

// database/migrations/..._create_courses_table.php
Schema::create('courses', function (Blueprint $table) {
    $table->id();
    $table->string('name');
    $table->string('code')->unique()->nullable();
    $table->text('description')->nullable();
    $table->timestamps();
});

// database/migrations/..._create_enrollments_table.php (Pivot for User-Course relationship)
Schema::create('enrollments', function (Blueprint $table) {
    $table->id();
    $table->foreignId('user_id')->constrained()->onDelete('cascade');
    $table->foreignId('course_id')->constrained()->onDelete('cascade');
    $table->string('role_in_course'); // e.g., 'student', 'teacher', 'assistant' - Specific context within course
    $table->timestamps();
    $table->unique(['user_id', 'course_id', 'role_in_course']); // Ensure unique enrollment type
});

// database/migrations/..._create_announcements_table.php
Schema::create('announcements', function (Blueprint $table) {
    $table->id();
    $table->foreignId('user_id')->comment('Author')->constrained()->onDelete('cascade');
    $table->string('title');
    $table->text('content');
    $table->timestamp('published_at')->nullable(); // Allows scheduling/drafts
    $table->timestamp('expires_at')->nullable();   // Optional expiry
    $table->boolean('is_pinned')->default(false);
    $table->timestamps();
});

// database/migrations/..._create_announcement_targets_table.php (Pivot for targeting)
Schema::create('announcement_targets', function (Blueprint $table) {
    $table->foreignId('announcement_id')->constrained()->onDelete('cascade');
    // Target specific courses or roles, or use MorphTo for more flexibility
    // Simple approach: Target courses
    $table->foreignId('course_id')->nullable()->constrained()->onDelete('cascade');
    // Or target roles (less granular)
    // $table->foreignId('role_id')->nullable()->constrained()->onDelete('cascade');
    $table->primary(['announcement_id', 'course_id']); // Adjust primary key based on target type
});


// database/migrations/..._create_resources_table.php
Schema::create('resources', function (Blueprint $table) {
    $table->id();
    $table->foreignId('user_id')->comment('Uploader')->constrained()->onDelete('cascade');
    $table->foreignId('course_id')->constrained()->onDelete('cascade'); // Link resource to a course
    $table->string('name'); // Display name
    $table->string('file_path'); // Path in storage (e.g., S3)
    $table->string('original_filename');
    $table->string('mime_type');
    $table->unsignedBigInteger('size');
    $table->text('description')->nullable();
    $table->timestamps();
});


// database/migrations/..._create_calendar_events_table.php
Schema::create('calendar_events', function (Blueprint $table) {
    $table->id();
    $table->foreignId('user_id')->nullable()->comment('Creator')->constrained()->onDelete('set null');
    $table->foreignId('course_id')->nullable()->constrained()->onDelete('cascade'); // Link event to a course?
    $table->string('title');
    $table->text('description')->nullable();
    $table->timestamp('start_time');
    $table->timestamp('end_time')->nullable();
    $table->boolean('all_day')->default(false);
    $table->string('type')->default('general'); // e.g., general, holiday, assignment, exam
    $table->string('color')->nullable(); // Color for frontend display
    $table->timestamps();
});
```


```php
// app/Models/User.php
namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Spatie\Permission\Traits\HasRoles; // Use Spatie trait

class User extends Authenticatable
{
    use Notifiable, HasRoles; // Include HasRoles

    // ... fillable, hidden, casts ...

    // Courses the user is enrolled in (as student, teacher, etc.)
    public function enrollments()
    {
        return $this->hasMany(Enrollment::class);
    }

    // Get courses directly (might specify role)
    public function coursesTeaching()
    {
        return $this->belongsToMany(Course::class, 'enrollments')
                    ->wherePivot('role_in_course', 'teacher');
    }

    public function coursesStudying()
    {
        return $this->belongsToMany(Course::class, 'enrollments')
                    ->wherePivot('role_in_course', 'student');
    }

    public function announcementsAuthored()
    {
        return $this->hasMany(Announcement::class);
    }

    public function resourcesUploaded()
    {
        return $this->hasMany(Resource::class);
    }

     // Relationship for parents to children (example, needs more logic)
     // public function children() { return $this->belongsToMany(User::class, 'parent_child', 'parent_id', 'child_id'); }
     // public function parents() { return $this->belongsToMany(User::class, 'parent_child', 'child_id', 'parent_id'); }
}

// app/Models/Course.php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Course extends Model
{
    protected $fillable = ['name', 'code', 'description'];

    public function enrollments()
    {
        return $this->hasMany(Enrollment::class);
    }

    public function students()
    {
        return $this->belongsToMany(User::class, 'enrollments')
                    ->wherePivot('role_in_course', 'student');
    }

    public function teachers()
    {
        return $this->belongsToMany(User::class, 'enrollments')
                    ->wherePivot('role_in_course', 'teacher');
    }

    public function resources()
    {
        return $this->hasMany(Resource::class);
    }

    public function announcements()
    {
        // Announcements specifically targeted at this course
        return $this->belongsToMany(Announcement::class, 'announcement_targets');
    }

    public function calendarEvents()
    {
        return $this->hasMany(CalendarEvent::class);
    }
}

// app/Models/Announcement.php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder; // For scope

class Announcement extends Model
{
    protected $fillable = ['user_id', 'title', 'content', 'published_at', 'expires_at', 'is_pinned'];
    protected $casts = ['published_at' => 'datetime', 'expires_at' => 'datetime', 'is_pinned' => 'boolean'];

    public function author()
    {
        return $this->belongsTo(User::class, 'user_id');
    }

    // Courses this announcement targets
    public function targetCourses()
    {
        return $this->belongsToMany(Course::class, 'announcement_targets');
    }

     // --- Scope for filtering announcements visible to a specific user ---
    public function scopeVisibleTo(Builder $query, User $user): Builder
    {
        return $query->where(function ($q) use ($user) {
            // Published and not expired
            $q->whereNotNull('published_at')
              ->where('published_at', '<=', now())
              ->where(function ($sub) {
                  $sub->whereNull('expires_at')
                      ->orWhere('expires_at', '>', now());
              });

            // Filter by target:
            // 1. Announcements targeted at courses the user is enrolled in
            $userCourseIds = $user->enrollments()->pluck('course_id')->unique()->toArray();
            if (!empty($userCourseIds)) {
                $q->whereHas('targetCourses', function ($subQ) use ($userCourseIds) {
                    $subQ->whereIn('courses.id', $userCourseIds);
                });
            } else {
                // If user has no courses, maybe they shouldn't see course-specific ones? Or only global?
                // This depends on requirements. Let's assume they only see global if no courses.
                $q->doesntHave('targetCourses'); // Only global announcements
            }

            // 2. OR Announcements with NO specific course target (global announcements)
             $q->orWhereDoesntHave('targetCourses'); // Include global ones

            // 3. Admins/specific roles might see all
            if ($user->hasRole('Admin') || $user->hasPermissionTo('view all announcements')) {
                 // Reset the target constraints if admin can see all
                 // This needs careful structure, maybe better handled in Controller/Policy
                 // For simplicity here, let's assume the base query handles published/expired
                 // and the controller adds an ->orWhere(fn($q) => $q) for admins.
            }
        })->orderBy('is_pinned', 'desc')->orderBy('published_at', 'desc');
    }
}

// app/Models/Resource.php
// app/Models/CalendarEvent.php
// ... (Define relationships similarly)
```



```php
// app/Policies/AnnouncementPolicy.php
namespace App\Policies;

use App\Models\Announcement;
use App\Models\User;
use Illuminate\Auth\Access\HandlesAuthorization;

class AnnouncementPolicy
{
    use HandlesAuthorization;

    // Admins can do anything
    public function before(User $user, $ability)
    {
        if ($user->hasRole('Admin')) {
            return true;
        }
    }

    public function viewAny(User $user): bool
    {
        // Anyone logged in can potentially view *some* announcements
        return true;
    }

    public function view(User $user, Announcement $announcement): bool
    {
        // More complex logic: Is the announcement published, not expired,
        // AND targeted at the user (or global)?
        // This logic is partly in the scope `visibleTo`, but policy enforces it.
        // Check if announcement ID exists in the result of the scope for the user.
        return Announcement::visibleTo($user)->where('id', $announcement->id)->exists();
    }

    public function create(User $user): bool
    {
        return $user->hasPermissionTo('create announcements');
    }

    public function update(User $user, Announcement $announcement): bool
    {
        // Only author or admin can update?
        return $user->id === $announcement->user_id || $user->hasRole('Admin');
    }

    // delete, publish, etc.
}


// app/Http/Requests/StoreAnnouncementRequest.php
namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreAnnouncementRequest extends FormRequest
{
    public function authorize(): bool
    {
        // Use the policy to check if the user can create
        return $this->user()->can('create', \App\Models\Announcement::class);
    }

    public function rules(): array
    {
        return [
            'title' => 'required|string|max:255',
            'content' => 'required|string',
            'publish_now' => 'required|boolean',
            'published_at' => 'nullable|date|required_if:publish_now,false|after_or_equal:now',
            'expires_at' => 'nullable|date|after:published_at',
            'target_course_ids' => 'nullable|array', // Array of course IDs
            'target_course_ids.*' => 'required|integer|exists:courses,id', // Validate each ID
            'is_pinned' => 'nullable|boolean',
        ];
    }
}

// app/Services/AnnouncementService.php
namespace App\Services;

use App\Models\Announcement;
use App\Models\User;
use App\Notifications\NewAnnouncementNotification; // Assume this exists
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification; // Facade

class AnnouncementService
{
    public function createAnnouncement(array $data, User $author): Announcement
    {
        return DB::transaction(function () use ($data, $author) {
            $announcement = $author->announcementsAuthored()->create([
                'title' => $data['title'],
                'content' => $data['content'],
                'published_at' => $data['publish_now'] ? now() : $data['published_at'],
                'expires_at' => $data['expires_at'] ?? null,
                'is_pinned' => $data['is_pinned'] ?? false,
            ]);

            // Attach targets
            if (!empty($data['target_course_ids'])) {
                $announcement->targetCourses()->attach($data['target_course_ids']);
            }
            // Could add logic for targeting roles here too

            // --- Trigger Notifications (if published now) ---
            if ($announcement->published_at && $announcement->published_at <= now()) {
                $this->notifyTargets($announcement);
            } else {
                // If scheduled, create a scheduled job to send notifications later
                // SendAnnouncementNotificationJob::dispatch($announcement)->delay($announcement->published_at);
            }

            return $announcement;
        });
    }

    public function notifyTargets(Announcement $announcement): void
    {
        $usersToNotify = collect();

        if ($announcement->targetCourses()->exists()) {
            // Find users enrolled in the target courses
            $courseIds = $announcement->targetCourses()->pluck('id')->toArray();
            $users = User::whereHas('enrollments', function ($q) use ($courseIds) {
                $q->whereIn('course_id', $courseIds); // Maybe specify ->where('role_in_course', 'student'); ?
            })->get();
            $usersToNotify = $usersToNotify->merge($users);
        } else {
            // Global announcement - notify relevant roles (e.g., all students and teachers?)
            // This logic needs refinement based on exact requirements
            $users = User::whereHas('roles', function ($q) {
                 $q->whereIn('name', ['Student', 'Teacher', 'Parent']); // Example roles
            })->get();
             $usersToNotify = $usersToNotify->merge($users);
        }

        // Ensure uniqueness and exclude the author?
        $uniqueUsers = $usersToNotify->unique('id')->reject(fn($user) => $user->id === $announcement->user_id);

        // Send notification using Laravel's Notification facade (queues automatically if Notification implements ShouldQueue)
        Notification::send($uniqueUsers, new NewAnnouncementNotification($announcement));
    }

    // updateAnnouncement, deleteAnnouncement methods...
}


// app/Http/Controllers/AnnouncementController.php
namespace App\Http\Controllers;

use App\Http\Requests\StoreAnnouncementRequest;
use App\Models\Announcement;
use App\Models\User;
use App\Services\AnnouncementService;
use Illuminate\Http\Request; // Use Illuminate\Http\Request
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia; // Example if using Inertia

class AnnouncementController extends Controller
{
    protected AnnouncementService $announcementService;

    public function __construct(AnnouncementService $announcementService)
    {
        $this->announcementService = $announcementService;
        // Apply policy middleware where appropriate
        $this->authorizeResource(Announcement::class, 'announcement');
    }

    public function index(Request $request) // Inject Request
    {
        /** @var User $user */
        $user = $request->user(); // Use injected request

        // Use the scope defined in the model
        $announcements = Announcement::visibleTo($user)
                            ->with('author:id,name') // Eager load author name
                            ->paginate(15);

        // Return view (Blade) or Inertia response
        // return view('announcements.index', compact('announcements'));
        return Inertia::render('Announcements/Index', ['announcements' => $announcements]);
    }

    public function create()
    {
         // Fetch courses if needed for targeting dropdown
         // $courses = Course::orderBy('name')->get(['id', 'name']);
         // return view('announcements.create', compact('courses'));
         return Inertia::render('Announcements/Create'/*, compact('courses')*/);
    }


    public function store(StoreAnnouncementRequest $request)
    {
        $this->announcementService->createAnnouncement($request->validated(), $request->user());

        return redirect()->route('announcements.index')->with('success', 'Comunicado criado com sucesso!');
    }

    public function show(Announcement $announcement) // Route model binding
    {
         // Authorization handled by authorizeResource or explicitly: $this->authorize('view', $announcement);
         // return view('announcements.show', compact('announcement'));
         return Inertia::render('Announcements/Show', ['announcement' => $announcement->load('author:id,name')]);
    }

    // edit, update, destroy methods...
}
```



```php
// app/Policies/ResourcePolicy.php - Simplified
// ... (use HandlesAuthorization)
public function viewAny(User $user): bool { return true; } // Can view the list page

public function view(User $user, Resource $resource): bool
{
    // Can view if user is enrolled in the resource's course OR is admin/teacher
    return $user->hasRole(['Admin', 'Teacher']) || $user->enrollments()->where('course_id', $resource->course_id)->exists();
}

public function create(User $user): bool
{
     return $user->hasPermissionTo('upload resources');
}

public function download(User $user, Resource $resource): bool
{
    // Same logic as view - can they access the course?
    return $this->view($user, $resource);
}

public function delete(User $user, Resource $resource): bool
{
    // Only uploader or Admin/Teacher with 'manage resources' perm?
    return $user->id === $resource->user_id || $user->hasPermissionTo('manage resources');
}
// ...

// app/Http/Requests/StoreResourceRequest.php
// ...
public function rules(): array {
    return [
        'course_id' => 'required|integer|exists:courses,id',
        'name' => 'required|string|max:255',
        'description' => 'nullable|string',
        'file' => 'required|file|mimes:pdf,doc,docx,ppt,pptx,xls,xlsx,jpg,png,mp4,zip|max:51200', // Example: max 50MB
    ];
}
// ...

// app/Services/ResourceUploadService.php
namespace App\Services;

use App\Models\Course;
use App\Models\Resource;
use App\Models\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class ResourceUploadService
{
    public function uploadResource(UploadedFile $file, array $data, User $uploader, Course $course): Resource
    {
        // Generate a unique path, e.g., courses/{course_id}/resources/{uuid}_{filename}
        $filename = Str::uuid() . '_' . $file->getClientOriginalName();
        $path = "courses/{$course->id}/resources/{$filename}";

        // Use Laravel Filesystem to store the file (e.g., on S3)
        $storedPath = Storage::disk(config('filesystems.default_resource_disk', 's3'))->putFileAs(
            "courses/{$course->id}/resources", // Directory
            $file,                           // File content
            $filename,                       // Desired filename
            'public'                         // Make it publicly accessible if needed, or use signed URLs
        );

        if (!$storedPath) {
            throw new \Exception("Falha ao fazer upload do arquivo.");
        }

        // Create database record
        $resource = $course->resources()->create([
            'user_id' => $uploader->id,
            'name' => $data['name'],
            'description' => $data['description'] ?? null,
            'file_path' => $storedPath, // Store the path returned by Storage::putFileAs
            'original_filename' => $file->getClientOriginalName(),
            'mime_type' => $file->getMimeType(),
            'size' => $file->getSize(),
        ]);

        return $resource;
    }

    public function getDownloadUrl(Resource $resource): string
    {
        $disk = Storage::disk(config('filesystems.default_resource_disk', 's3'));

        // If using private files on S3, generate a temporary signed URL
        if (config('filesystems.disks.s3.visibility') === 'private') {
             return $disk->temporaryUrl($resource->file_path, now()->addMinutes(15)); // URL valid for 15 mins
        }

        // Otherwise, return the public URL
        return $disk->url($resource->file_path);
    }
}


// app/Http/Controllers/ResourceController.php
// ... (Inject Service, Use Policy, Request)

public function store(StoreResourceRequest $request, ResourceUploadService $uploadService)
{
    $this->authorize('create', Resource::class);

    $course = Course::findOrFail($request->input('course_id'));
    // Optional: Check if user is actually a teacher for this course
    // if (! $request->user()->coursesTeaching()->where('id', $course->id)->exists()) { abort(403); }

    $resource = $uploadService->uploadResource(
        $request->file('file'),
        $request->safe()->only(['name', 'description']), // Use safe()->only()
        $request->user(),
        $course
    );

    return redirect()->route('courses.show', $course)->with('success', 'Recurso adicionado!'); // Redirect to course page
}

public function download(Resource $resource, ResourceUploadService $uploadService) // Route model binding
{
    $this->authorize('download', $resource);

    $downloadUrl = $uploadService->getDownloadUrl($resource);

    // Option 1: Redirect to the URL (good for S3 signed URLs or public URLs)
    return redirect()->away($downloadUrl);

    // Option 2: Stream download (forces download dialog, hides actual URL)
    // return Storage::disk(config('filesystems.default_resource_disk', 's3'))
    //         ->download($resource->file_path, $resource->original_filename);
}

// index method would likely list resources for a specific course
// public function index(Course $course, Request $request) { ... $this->authorize(...); $resources = $course->resources()->paginate(); ... }
```


```php
// app/Http/Controllers/Api/CalendarEventController.php
namespace App\Http\Controllers\Api; // Note the API namespace

use App\Http\Controllers\Controller;
use App\Models\CalendarEvent;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class CalendarEventController extends Controller
{
    public function index(Request $request)
    {
        $user = Auth::user();
        if (!$user) {
            return response()->json(['error' => 'Unauthenticated'], 401);
        }

        // Validate start/end date inputs from FullCalendar fetchInfo
        $request->validate([
            'start' => 'required|date_format:Y-m-d',
            'end' => 'required|date_format:Y-m-d',
        ]);

        $start = $request->input('start');
        $end = $request->input('end');

        $query = CalendarEvent::query();

        // Basic filtering: Get events within the requested range
        $query->where(function ($q) use ($start, $end) {
            $q->where(function ($sub) use ($start, $end) { // Events starting within range
                $sub->where('start_time', '>=', $start)->where('start_time', '<', $end);
            })->orWhere(function ($sub) use ($start, $end) { // Events ending within range
                $sub->where('end_time', '>', $start)->where('end_time', '<=', $end);
            })->orWhere(function ($sub) use ($start, $end) { // Events spanning the entire range
                $sub->where('start_time', '<', $start)->where('end_time', '>', $end);
            });
        });


        // --- Authorization/Relevance Filtering ---
        // Show global events (no course_id) OR events for courses user is enrolled in
        $userCourseIds = $user->enrollments()->pluck('course_id')->toArray();

        $query->where(function ($q) use ($userCourseIds, $user) {
            // Global events (no course assigned) are visible to all logged-in users
            $q->whereNull('course_id');

            // Add events for courses the user is enrolled in
            if (!empty($userCourseIds)) {
                $q->orWhereIn('course_id', $userCourseIds);
            }

             // Teachers/Admins might see events they created even if not linked to their courses?
             // if ($user->hasRole(['Admin', 'Teacher'])) {
             //     $q->orWhere('user_id', $user->id);
             // }
        });

        $events = $query->get([
            'id', 'title', 'start_time as start', 'end_time as end', // Alias for FullCalendar
            'all_day as allDay', 'description', 'color', 'type', 'course_id' // Include needed fields
        ]);

        return response()->json($events);
    }

    // store, update, destroy methods would go here, with authorization checks
}

// Define API route in routes/api.php
// Route::middleware('auth:sanctum')->get('/calendar-events', [App\Http\Controllers\Api\CalendarEventController::class, 'index']);
```


```javascript
// Assuming FullCalendar is loaded and you have a div#calendar
import { Calendar } from '@fullcalendar/core';
import dayGridPlugin from '@fullcalendar/daygrid';
import timeGridPlugin from '@fullcalendar/timegrid';
import listPlugin from '@fullcalendar/list';
import interactionPlugin from '@fullcalendar/interaction'; // For date clicking, selecting, etc.

document.addEventListener('DOMContentLoaded', function() {
  const calendarEl = document.getElementById('calendar');
  if (calendarEl) {
      const calendar = new Calendar(calendarEl, {
        plugins: [dayGridPlugin, timeGridPlugin, listPlugin, interactionPlugin],
        initialView: 'dayGridMonth', // Default view
        headerToolbar: {
          left: 'prev,next today',
          center: 'title',
          right: 'dayGridMonth,timeGridWeek,listWeek'
        },
        locale: 'pt-br', // Set locale if needed
        buttonText: { // Translate buttons
             today: 'Hoje',
             month: 'Mês',
             week: 'Semana',
             list: 'Lista'
        },
        events: {
            // Use a function to fetch events from the Laravel API
            url: '/api/calendar-events', // Your API endpoint
            method: 'GET',
            failure: function(err) {
                console.error("Erro ao carregar eventos:", err);
                alert('Não foi possível carregar os eventos do calendário.');
            },
            // Optional: Add extra parameters if needed, like filtering
            // extraParams: function() { return { custom_param: 'something' }; }

            // Optional: Set headers, like Authorization if using token auth
            // headers: { 'Authorization': 'Bearer ' + your_token }
        },
        // Optional: Handle date clicks, event clicks, etc.
        // dateClick: function(info) { ... },
        // eventClick: function(info) { ... },
        loading: function(isLoading) {
            // Show/hide a loading indicator
            // console.log('Calendar loading:', isLoading);
        },
        eventTimeFormat: { // Example time format
            hour: '2-digit',
            minute: '2-digit',
            meridiem: false,
            hour12: false
        }
      });
      calendar.render();
  }
});
```

---
