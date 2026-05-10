import SwiftUI

struct GenerateKeySheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var keyType = "ed25519"
    @State private var description = ""
    @State private var tagsText = ""
    @FocusState private var firstFieldFocused: Bool

    var body: some View {
        VStack(spacing: 16) {
            Text("Generate SSH Key")
                .font(.title2)

            Form {
                TextField("Name", text: $name)
                    .focused($firstFieldFocused)

                Picker("Key Type", selection: $keyType) {
                    Text("Ed25519 (recommended)").tag("ed25519")
                    Text("RSA 2048").tag("rsa2048")
                    Text("RSA 4096").tag("rsa4096")
                }

                TextField("Description", text: $description)
                TextField("Tags (comma separated)", text: $tagsText)
            }
            .formStyle(.grouped)

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Generate") {
                    let tags = tagsText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                    Task {
                        await appState.generateKey(
                            name: name,
                            keyType: keyType,
                            description: description,
                            tags: tags
                        )
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(name.isEmpty)
            }
        }
        .padding()
        .frame(width: 400, height: 350)
        .task {
            try? await Task.sleep(for: .milliseconds(100))
            firstFieldFocused = true
        }
    }
}
