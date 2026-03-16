### Folder description

- **admin** – project administration, ethics, recruitment and data management plans  
- **design** – study design and protocol documentation  
- **code** – preprocessing and analysis pipelines  
- **data** – raw, derivative, and confidential datasets  
- **analysis_outputs** – intermediate and final analysis results  
- **manuscript** – drafts and submission material  
- **references** – literature and reference atlases

- ## Study Structure
```
[study_name]/
├── data
│   ├── rawdata
│   │   ├── cohort_1
│   │   │   ├── modality_1
│   │   │   └── modality_2
│   │   └── cohort_2
│   │       ├── modality_1
│   │       └── modality_2
│   └── derivatives
│       ├── preprocessing
│       └── analyses
│
├── code
│   ├── preprocessing
│   └── analyses
│       ├── pipeline_1
│       ├── pipeline_2
│       └── pipeline_3
│
├── results
│   ├── figures
│   └── tables
│
└── manuscript
    ├── drafts
    ├── submissions
    └── literature
```
- ## Project Structure (vCREATEAM)

```
[project_name]/
│
├── admin
│   ├── recruitment
│   │   └── planning
│   ├── ethics
│   ├── dmp
│   │   └── sops
│   ├── pre_registration
│   └── tasks
│       ├── instructions
│       ├── scripts
│       └── stimuli
│
├── design
│   └── protocol_description
│
├── code
│   └── pipelines_and_scripts
│       ├── preproc_1
│       ├── analysis_processing_2
│       ├── analysis_processing_3
│       └── final_scripts
│
├── data
│   ├── raw
│   │   ├── cohort_1
│   │   │   ├── modality_1
│   │   │   └── modality_2
│   │   └── cohort_2
│   │       ├── modality_1
│   │       └── modality_2
│   │
│   ├── derivatives
│   │   ├── sub
│   │   │   └── ses
│   │   └── clinical_cognitive
│   │
│   ├── confidential
│   │   ├── participant_data
│   │   └── subj_identifiers
│   │
│   └── mods
│       ├── atlases
│       └── masks
│
├── analysis_outputs
│   ├── intermediate
│   │   ├── figures
│   │   └── tables
│   └── final
│
├── manuscript
│   └── drafts
│       └── submissions
│
└── references
    └── atlas
        └── literature
```

- ## Organizational Structure

```
organization/
│
├── administrative
│   ├── resources
│   │   ├── ethics_and_good_practices
│   │   ├── data_management
│   │   ├── icm_magasin
│   │   └── support
│   │
│   ├── planning
│   │
│   └── misc
│       ├── logos
│       └── pictures
│
├── education
│   ├── tutorials
│   ├── books
│   └── courses
│
├── communication
│   ├── public_engagement
│   ├── conferences
│   │   ├── presented_posters
│   │   ├── presented_talks
│   │   └── conference_debriefings
│   │
│   ├── journal_clubs
│   └── invited_speakers
│
├── meetings
│   ├── retreats
│   ├── project_presentations
│   └── rehearsals
│
└── ideas
    ├── notes
    ├── brainstorming
    └── sources
    ```
