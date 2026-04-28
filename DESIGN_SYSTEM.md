# Enterprise Cybersecurity Operations Platform - Design System

## Overview
This application has been redesigned as a professional enterprise-grade cybersecurity operations platform, inspired by industry leaders like Datadog, GitHub Enterprise, Linear, Splunk, Kibana, and Bloomberg terminals.

## Design Philosophy
- **Minimal**: Remove visual noise and focus on information density
- **Professional**: Enterprise-grade appearance suitable for Fortune 500 SOC teams
- **Monochrome-First**: Primary palette built on grayscale with limited accent colors
- **Information-Oriented**: Dense layouts with structured data presentations
- **No AI Aesthetics**: Avoid futuristic gradients, glassmorphism, or flashy effects

## Color Palette

### Monochrome Base (Light Mode Only)
```css
--white: #ffffff
--off-white: #f9fafb
--gray-50: #f3f4f6
--gray-100: #e5e7eb
--gray-200: #d1d5db
--gray-300: #bcc2c9
--gray-400: #9ca3af
--gray-500: #6b7280
--gray-600: #4b5563
--gray-700: #374151
--gray-800: #1f2937
--black: #000000
```

### Accent Colors (ONLY for specific purposes)
- **Critical Severity**: #dc2626 (Red - for immediate threats)
- **High Severity**: #ea580c (Orange - for elevated risk)
- **Medium Severity**: #f59e0b (Amber - for medium risk)
- **Low Severity**: #10b981 (Green - for low priority)
- **Active State**: #0369a1 (Blue - for navigation and links)
- **Active State Light**: #e0f2fe (Light blue - for focus states)

## Typography

### Font Stack
```css
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', 'IBM Plex Sans', 'Helvetica Neue', sans-serif;
```

### Hierarchy
- **Page Title**: 1.25rem, weight 700, letter-spacing -0.01em
- **Section Title**: 0.9375rem, weight 700
- **Body Text**: 0.9375rem, weight 400
- **Labels**: 0.75rem, weight 700, text-transform uppercase, letter-spacing 0.05em
- **Metadata**: 0.8125rem, weight 500
- **Table Headers**: 0.8125rem, weight 700, text-transform uppercase

## Components

### Buttons
- **Primary**: Solid black background, white text (no gradients)
- **Secondary**: White background, black text, gray border
- **Tertiary**: Transparent background, blue text
- **Danger**: Red background, white text
- Flat design with subtle hover effects (no shadow expansion)
- Border radius: 6px (compact)

### Cards & Panels
- Border: 1px solid #e5e7eb (subtle)
- Border radius: 6px (max)
- Shadow: 0 1px 2px rgba(0,0,0,0.05) (minimal)
- No floating aesthetic or gradients
- Padding: 1rem (dense)

### Tables
- Enterprise data-table appearance
- Sticky headers with gray-50 background
- Zebra striping: None (too flashy)
- Subtle row hover: gray-50 background
- Dense row height for information density
- Column separators: Subtle 1px borders

### Stat Cards
- Clean white background with gray border
- Large bold numbers (1.875rem, weight 800)
- Small uppercase labels (0.75rem)
- Minimal trend text (secondary color)
- Color coding for severity only

### Badges & Pills
- **Badges**: Compact, 0.7rem font, 4px border-radius
  - Critical: Red background, dark red text
  - High: Orange background, dark orange text
  - Medium: Amber background, dark amber text
  - Low: Green background, dark green text
- **Pills**: Rounded (12px), larger padding, used for status

### Forms
- Input height: 2.5rem (40px)
- Border: 1px solid #e5e7eb
- Focus state: Blue border + light blue shadow (0 0 0 3px #e0f2fe)
- Placeholder: Gray-400 text
- No background color change on focus

## Layout

### Page Structure
- Header: White background, thin bottom border
- Navigation: Thin top navigation bar with underline active indicator
- Main content: Max-width 1600px, centered
- Padding: Compact (1.5rem sides)

### Grid Systems
- **Stats Grid**: Auto-fit columns, min 240px
- **Two-Col Layout**: Equal split, 1rem gap
- **Filters Grid**: Auto-fit, min 180px
- Responsive: Stack to single column on mobile

### Spacing
- Gap between major sections: 1rem
- Padding within cards: 1rem
- Padding within stats: 1.25rem
- Field gap: 0.375rem

## Data Visualization (Recharts)

### Charts
- Background: White
- Grid: Subtle gray (#e5e7eb), no dashed lines
- Axes: Gray-500 text (#6b7280)
- Bar colors: Grayscale (#374151, #4b5563, #6b7280, #9ca3af, #bcc2c9)
- Line colors: Gray-600 (#4b5563)
- Accent for attacks: Red (#dc2626)
- Labels: 12px, gray text
- No gradients, no glowing effects

## Modals & Panels

### Modal Styling
- Background: White
- Border: 1px solid #e5e7eb
- Border radius: 6px
- Shadow: 0 4px 8px rgba(0,0,0,0.1)
- Overlay: rgba(0,0,0,0.4)

### Side Panels
- Slide-in from right
- White background
- Same border and shadow as modals
- Positioned absolutely
- 380px max width

## Graph Visualization

### Node Colors (Professional Monochrome)
- **User**: Gray (#6b7280)
- **Window**: Light Gray (#9ca3af)
- **Detection Pattern**: Dark Gray (#374151)
- **MITRE Technique**: Red (#dc2626) - Accent only
- **Playbook**: Indigo (#6366f1) - Accent only
- Border: Darker shade of fill color
- Highlight: Lighter shade on selection

### Edge Colors
- Default edges: Light Gray (#d1d5db)
- Important edges: Gray (#6b7280)
- Subtle distinction (not bright colors)

## States & Feedback

### Loading
- Spinner: 32px, 2px border, blue (#0369a1) top color

### Error
- Background: #fef2f2 (light red)
- Border left: 3px solid #dc2626
- Text: Gray-700

### Empty States
- Centered text
- Gray-400 color
- Message: "No data available"

### Hover & Active States
- Hover: Background color shift to gray-50
- Active: Blue (#0369a1) for navigation
- Focus: Blue border + light blue shadow (0 0 0 3px #e0f2fe)

## Shadows

```css
--shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);  /* subtle, used on headers */
--shadow: 0 2px 4px rgba(0, 0, 0, 0.08);     /* cards, panels */
--shadow-lg: 0 4px 8px rgba(0, 0, 0, 0.1);   /* modals */
```

No glowing or oversized shadows. All shadows are subtle and restrained.

## Borders

- **Standard Border**: 1px solid #e5e7eb (main divider)
- **Subtle Border**: 1px solid #e9ecef (light divider, within sections)
- **Active Border**: 1px solid #0369a1 (focused elements)

## What NOT to Do

❌ No neon blue/purple gradients
❌ No glowing buttons or borders
❌ No glassmorphism effects
❌ No oversized rounded corners (max 8px)
❌ No flashy shadows
❌ No colorful cards (all white/gray)
❌ No cyan/purple AI palette
❌ No background patterns or textures
❌ No multiple accent colors in buttons
❌ No rounded pill buttons for primary actions

## Browser Support

- Modern browsers (Chrome, Firefox, Safari, Edge)
- Light mode only
- CSS variables for theming
- Flexbox and CSS Grid for layouts
- No experimental features

## Accessibility

- High contrast ratios for readability
- Large clickable areas (32px minimum)
- Focus states clearly visible
- Semantic HTML structure
- Responsive design for all screen sizes
- Reduced motion support

## Implementation Notes

1. All colors are defined in `:root` CSS variables
2. Component classes follow BEM-like naming (e.g., `.btn-primary`)
3. Recharts components customize colors via Tooltip props
4. Graph visualization uses vis-network with professional color mappings
5. Monochrome text (#111827) for all primary content
6. Severity colors only appear in badges, scores, and accent elements
7. Charts avoid decorative elements (no dots, no dashed grids)
8. Tables use full-width borders for clear column separation

## Vendor Integration

Reserved spacing and styling for integrating:
- AWS logo/badge
- Azure logo/badge
- Kubernetes logo/badge
- Docker logo/badge
- Neo4j logo/badge
- OpenSearch logo/badge
- Kafka logo/badge
- PostgreSQL logo/badge

Use `.vendor-logo` class: 24px × 24px, centered, inline-flex
